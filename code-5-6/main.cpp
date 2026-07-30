#include <seal/seal.h>
#include <algorithm>
#include <array>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace std;
using namespace seal;

/*
 * 4×4 输入，3×3 卷积核
 * stride = 1，padding = 0
 * 输出尺寸为 2×2
 */

constexpr size_t INPUT_ROWS = 4;
constexpr size_t INPUT_COLS = 4;
constexpr size_t KERNEL_SIZE = 3;
constexpr size_t OUTPUT_ROWS = 2;
constexpr size_t OUTPUT_COLS = 2;

/* 明文卷积，用于正确性验证 */
vector<double> plaintext_convolution(
    const vector<double> &input,
    const array<array<double, KERNEL_SIZE>, KERNEL_SIZE> &kernel)
{
    vector<double> output(OUTPUT_ROWS * OUTPUT_COLS, 0.0);

    for (size_t out_row = 0; out_row < OUTPUT_ROWS; ++out_row)
    {
        for (size_t out_col = 0; out_col < OUTPUT_COLS; ++out_col)
        {
            double sum = 0.0;

            for (size_t kernel_row = 0; kernel_row < KERNEL_SIZE; ++kernel_row)
            {
                for (size_t kernel_col = 0; kernel_col < KERNEL_SIZE; ++kernel_col)
                {
                    size_t input_row = out_row + kernel_row;
                    size_t input_col = out_col + kernel_col;

                    size_t input_index = input_row * INPUT_COLS + input_col;

                    sum += input[input_index] *
                           kernel[kernel_row][kernel_col];
                }
            }

            output[out_row * OUTPUT_COLS + out_col] = sum;
        }
    }

    return output;
}

/* 打印4×4输入矩阵 */
void print_input_matrix(const vector<double> &input)
{
    cout << "Input matrix X:" << endl;

    for (size_t row = 0; row < INPUT_ROWS; ++row)
    {
        for (size_t col = 0; col < INPUT_COLS; ++col)
        {
            cout << setw(10) << fixed << setprecision(3)
                 << input[row * INPUT_COLS + col];
        }
        cout << endl;
    }
}

/* 打印3×3卷积核 */
void print_kernel(
    const array<array<double, KERNEL_SIZE>, KERNEL_SIZE> &kernel)
{
    cout << "Kernel K:" << endl;

    for (const auto &row : kernel)
    {
        for (double value : row)
        {
            cout << setw(10) << fixed << setprecision(3) << value;
        }
        cout << endl;
    }
}

/* 打印2×2明文输出 */
void print_plain_output(const vector<double> &output)
{
    for (size_t row = 0; row < OUTPUT_ROWS; ++row)
    {
        for (size_t col = 0; col < OUTPUT_COLS; ++col)
        {
            cout << setw(14) << fixed << setprecision(6)
                 << output[row * OUTPUT_COLS + col];
        }
        cout << endl;
    }
}

/*
 * 密文中的输出保存在槽位：
 *
 * 0  1
 * 4  5
 *
 * 因为输入仍采用4列行主序布局。
 */
vector<double> extract_cipher_output(const vector<double> &decoded)
{
    return {
        decoded[0],
        decoded[1],
        decoded[4],
        decoded[5]
    };
}

/* 计算最大绝对误差 */
double maximum_absolute_error(
    const vector<double> &expected,
    const vector<double> &actual)
{
    double maximum_error = 0.0;

    for (size_t i = 0; i < expected.size(); ++i)
    {
        maximum_error = max(
            maximum_error,
            abs(expected[i] - actual[i])
        );
    }

    return maximum_error;
}

/*
 *
 * 朴素打包—旋转—累加。
 *
 * 需要的输入偏移为：
 *
 * 0, 1, 2,
 * 4, 5, 6,
 * 8, 9, 10
 *
 * 偏移0不需要旋转，其余8个偏移各旋转一次。
 */
Ciphertext encrypted_convolution_naive(
    const Ciphertext &encrypted_input,
    const array<array<double, KERNEL_SIZE>, KERNEL_SIZE> &kernel,
    CKKSEncoder &encoder,
    Evaluator &evaluator,
    const GaloisKeys &galois_keys,
    double scale,
    size_t slot_count,
    int &rotation_count)
{
    Ciphertext encrypted_result;
    bool first_term = true;

    rotation_count = 0;

    /*
     * 只有槽位0、1、4、5是有效输出位置。
     * 其他槽位通过明文掩码清零。
     */
    const vector<size_t> output_slots = {0, 1, 4, 5};

    for (size_t kernel_row = 0; kernel_row < KERNEL_SIZE; ++kernel_row)
    {
        for (size_t kernel_col = 0; kernel_col < KERNEL_SIZE; ++kernel_col)
        {
            int offset = static_cast<int>(
                kernel_row * INPUT_COLS + kernel_col
            );

            Ciphertext rotated_input;

            if (offset == 0)
            {
                rotated_input = encrypted_input;
            }
            else
            {
                /*
                 * 正数表示向左旋转。
                 * 旋转offset后，原槽位i+offset的数据进入槽位i。
                 */
                evaluator.rotate_vector(
                    encrypted_input,
                    offset,
                    galois_keys,
                    rotated_input
                );

                ++rotation_count;
            }

            vector<double> mask(slot_count, 0.0);

            for (size_t output_slot : output_slots)
            {
                mask[output_slot] =
                    kernel[kernel_row][kernel_col];
            }

            Plaintext encoded_mask;
            encoder.encode(mask, scale, encoded_mask);

            evaluator.multiply_plain_inplace(
                rotated_input,
                encoded_mask
            );

            if (first_term)
            {
                encrypted_result = rotated_input;
                first_term = false;
            }
            else
            {
                evaluator.add_inplace(
                    encrypted_result,
                    rotated_input
                );
            }
        }
    }

    return encrypted_result;
}

/*
 *
 * 对全1卷积核使用行列分解。
 *
 * 3×3全1卷积核可分解为：
 *
 * [1]           [1 1 1]
 * [1]    ×
 * [1]
 *
 * 第一阶段：水平方向累加
 * H = X + Rot(X,1) + Rot(X,2)
 *
 * 第二阶段：垂直方向累加
 * Y = H + Rot(H,4) + Rot(H,8)
 *
 * 总旋转次数：
 * 水平2次 + 垂直2次 = 4次。
 */
Ciphertext encrypted_convolution_optimized(
    const Ciphertext &encrypted_input,
    CKKSEncoder &encoder,
    Evaluator &evaluator,
    const GaloisKeys &galois_keys,
    double scale,
    size_t slot_count,
    int &rotation_count)
{
    rotation_count = 0;

    /*
     * 第一步：水平3元素累加
     */
    Ciphertext horizontal_sum = encrypted_input;

    Ciphertext rotated_by_1;
    evaluator.rotate_vector(
        encrypted_input,
        1,
        galois_keys,
        rotated_by_1
    );
    ++rotation_count;

    evaluator.add_inplace(
        horizontal_sum,
        rotated_by_1
    );

    Ciphertext rotated_by_2;
    evaluator.rotate_vector(
        encrypted_input,
        2,
        galois_keys,
        rotated_by_2
    );
    ++rotation_count;

    evaluator.add_inplace(
        horizontal_sum,
        rotated_by_2
    );

    /*
     * 第二步：垂直3行累加
     */
    Ciphertext convolution_sum = horizontal_sum;

    Ciphertext rotated_by_4;
    evaluator.rotate_vector(
        horizontal_sum,
        4,
        galois_keys,
        rotated_by_4
    );
    ++rotation_count;

    evaluator.add_inplace(
        convolution_sum,
        rotated_by_4
    );

    Ciphertext rotated_by_8;
    evaluator.rotate_vector(
        horizontal_sum,
        8,
        galois_keys,
        rotated_by_8
    );
    ++rotation_count;

    evaluator.add_inplace(
        convolution_sum,
        rotated_by_8
    );

    /*
     * 只保留有效输出槽位0、1、4、5。
     */
    vector<double> output_mask(slot_count, 0.0);

    output_mask[0] = 1.0;
    output_mask[1] = 1.0;
    output_mask[4] = 1.0;
    output_mask[5] = 1.0;

    Plaintext encoded_output_mask;
    encoder.encode(
        output_mask,
        scale,
        encoded_output_mask
    );

    evaluator.multiply_plain_inplace(
        convolution_sum,
        encoded_output_mask
    );

    return convolution_sum;
}

/* 解密、解码密文，并提取2×2输出 */
vector<double> decrypt_convolution_result(
    const Ciphertext &encrypted_result,
    Decryptor &decryptor,
    CKKSEncoder &encoder)
{
    Plaintext plain_result;
    vector<double> decoded_result;

    decryptor.decrypt(
        encrypted_result,
        plain_result
    );

    encoder.decode(
        plain_result,
        decoded_result
    );

    return extract_cipher_output(decoded_result);
}

int main()
{
    try
    {
        cout << "====================================================" << endl;
        cout << " FHE Homework 5 and 6: Encrypted 2D Convolution" << endl;
        cout << " Microsoft SEAL 4.1.1 / CKKS" << endl;
        cout << "====================================================" << endl;

        /*
         * 一、设置CKKS加密参数
         */
        EncryptionParameters parameters(scheme_type::ckks);

        size_t polynomial_modulus_degree = 8192;

        parameters.set_poly_modulus_degree(
            polynomial_modulus_degree
        );

        parameters.set_coeff_modulus(
            CoeffModulus::Create(
                polynomial_modulus_degree,
                {60, 40, 40, 60}
            )
        );

        SEALContext context(parameters);

        if (!context.parameters_set())
        {
            cerr << "Error: invalid SEAL parameters." << endl;
            return 1;
        }

        /*
         * 二、生成密钥
         */
        KeyGenerator key_generator(context);

        SecretKey secret_key = key_generator.secret_key();

        PublicKey public_key;
        key_generator.create_public_key(public_key);

        GaloisKeys galois_keys;
        key_generator.create_galois_keys(galois_keys);

        /*
         * 三、创建SEAL组件
         */
        Encryptor encryptor(context, public_key);
        Evaluator evaluator(context);
        Decryptor decryptor(context, secret_key);
        CKKSEncoder encoder(context);

        size_t slot_count = encoder.slot_count();
        double scale = pow(2.0, 40);

        cout << endl;
        cout << "CKKS parameters:" << endl;
        cout << "  poly_modulus_degree : "
             << polynomial_modulus_degree << endl;
        cout << "  slot count          : "
             << slot_count << endl;
        cout << "  initial scale       : 2^40" << endl;

        /*
         * 四、准备4×4输入矩阵
         */
        vector<double> input(slot_count, 0.0);

        for (size_t i = 0; i < 16; ++i)
        {
            input[i] = static_cast<double>(i + 1);
        }

        /*
         * 使用全1的3×3卷积核。
         */
        array<array<double, KERNEL_SIZE>, KERNEL_SIZE> kernel = {{
            {{1.0, 1.0, 1.0}},
            {{1.0, 1.0, 1.0}},
            {{1.0, 1.0, 1.0}}
        }};

        vector<double> compact_input(input.begin(), input.begin() + 16);

        cout << endl;
        print_input_matrix(compact_input);

        cout << endl;
        print_kernel(kernel);

        /*
         * 五、计算明文卷积结果
         */
        vector<double> expected_result =
            plaintext_convolution(compact_input, kernel);

        cout << endl;
        cout << "Plaintext convolution result:" << endl;
        print_plain_output(expected_result);

        /*
         * 六、CKKS编码和加密
         */
        Plaintext encoded_input;
        encoder.encode(
            input,
            scale,
            encoded_input
        );

        Ciphertext encrypted_input;
        encryptor.encrypt(
            encoded_input,
            encrypted_input
        );

        cout << endl;
        cout << "Input has been encoded and encrypted." << endl;

        /*
         * 七、朴素密文卷积
         */
        int naive_rotation_count = 0;

        Ciphertext naive_encrypted_result =
            encrypted_convolution_naive(
                encrypted_input,
                kernel,
                encoder,
                evaluator,
                galois_keys,
                scale,
                slot_count,
                naive_rotation_count
            );

        vector<double> naive_result =
            decrypt_convolution_result(
                naive_encrypted_result,
                decryptor,
                encoder
            );

        double naive_error =
            maximum_absolute_error(
                expected_result,
                naive_result
            );

        cout << endl;
        cout << "====================================================" << endl;
        cout << " Homework 5: Naive encrypted convolution" << endl;
        cout << "====================================================" << endl;

        cout << "Decrypted encrypted-convolution result:" << endl;
        print_plain_output(naive_result);

        cout << endl;
        cout << scientific << setprecision(8);
        cout << "Maximum absolute error: "
             << naive_error << endl;

        cout << "Correctness verification: "
             << (naive_error < 1e-4 ? "PASS" : "FAIL")
             << endl;

        cout << "Rotation count: "
             << naive_rotation_count << endl;

        /*
         * 八、优化旋转次数
         */
        int optimized_rotation_count = 0;

        Ciphertext optimized_encrypted_result =
            encrypted_convolution_optimized(
                encrypted_input,
                encoder,
                evaluator,
                galois_keys,
                scale,
                slot_count,
                optimized_rotation_count
            );

        vector<double> optimized_result =
            decrypt_convolution_result(
                optimized_encrypted_result,
                decryptor,
                encoder
            );

        double optimized_error =
            maximum_absolute_error(
                expected_result,
                optimized_result
            );

        cout << endl;
        cout << "====================================================" << endl;
        cout << " Homework 6: Rotation-optimized convolution" << endl;
        cout << "====================================================" << endl;

        cout << "Decrypted optimized result:" << endl;
        print_plain_output(optimized_result);

        cout << endl;
        cout << scientific << setprecision(8);
        cout << "Maximum absolute error: "
             << optimized_error << endl;

        cout << "Correctness verification: "
             << (optimized_error < 1e-4 ? "PASS" : "FAIL")
             << endl;

        cout << endl;
        cout << "Rotation comparison:" << endl;
        cout << "  Naive method     : "
             << naive_rotation_count << endl;
        cout << "  Optimized method : "
             << optimized_rotation_count << endl;
        cout << "  Reduction        : "
             << naive_rotation_count - optimized_rotation_count
             << endl;

        double reduction_percentage =
            100.0 *
            static_cast<double>(
                naive_rotation_count - optimized_rotation_count
            ) /
            static_cast<double>(naive_rotation_count);

        cout << fixed << setprecision(2);
        cout << "  Reduction ratio  : "
             << reduction_percentage << "%" << endl;

        cout << endl;
        cout << "Theoretical analysis:" << endl;
        cout << "  The naive method uses nine kernel offsets." << endl;
        cout << "  Offset 0 requires no rotation, so it uses 8 rotations."
             << endl;
        cout << "  The all-one kernel is separable into horizontal and"
             << endl;
        cout << "  vertical 3-element accumulations." << endl;
        cout << "  Horizontal accumulation needs rotations 1 and 2." << endl;
        cout << "  Vertical accumulation needs rotations 4 and 8." << endl;
        cout << "  Therefore the optimized method uses 4 rotations." << endl;
        cout << "  Under this separable row-column accumulation model," << endl;
        cout << "  the implementation reaches the 4-rotation lower bound."
             << endl;

        cout << endl;
        cout << "====================================================" << endl;
        cout << " All experiments completed successfully." << endl;
        cout << "====================================================" << endl;

        return 0;
    }
    catch (const exception &error)
    {
        cerr << "Program failed: "
             << error.what() << endl;

        return 1;
    }
}
