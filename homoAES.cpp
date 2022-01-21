#include <iostream>
#include <tfhe/tfhe_core.h>
#include <tfhe/tfhe.h>
#include <time.h>

using namespace std;

// 本代码全部基于门电路计算而来，如bootsXOR门(异或)， bootsMUX门

// extern void sm4_setkey(unsigned long RoundKey[], unsigned char key[]);
extern long AESKeyExpansion(unsigned char roundKeySchedule[],
                            unsigned char key[], int keyBits);

const double clocks2seconds = 1. / CLOCKS_PER_SEC;

const int byte_mul2[8] = {0, 0, 0, 0, 0, 0, 0, 0};

// extern unsigned char SboxTable[16][16];
static const unsigned char SboxTable[16][16] =
    {
        //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  //0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  //1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  //2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  //3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  //4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  //5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  //6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  //7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  //8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  //9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  //A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  //B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  //C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  //D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  //E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}; //F

// 组成整个table,完成
void HexToBinStr(int hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        bin_str[i] = hex % 2;
        hex /= 2;
    }
}

void BinStrToHex(int &dec_hex, int *bin_str)
{
    for (int i = 0; i < 8; ++i)
    {
        dec_hex += bin_str[i] * pow(2, i);
    }
}

//实现2个8bit的XOR函数
void XOR_Two(LweSample *result, LweSample *a, LweSample *b, const TFheGateBootstrappingCloudKeySet *bk,
             TFheGateBootstrappingSecretKeySet *key)
{
    for (int i = 0; i < 8; i++)
    {
        bootsXOR(result + i, a + i, b + i, bk);
        // cout << bootsSymDecrypt(result + i, key) << " ";
    }
    // cout<<endl;
}

//实现4个8bit的XOR函数
void XOR_Four(LweSample *result, LweSample *a, LweSample *b, LweSample *c, LweSample *d,
              const TFheGateBootstrappingCloudKeySet *bk,
              TFheGateBootstrappingSecretKeySet *key)
{
    XOR_Two(result, a, b, bk, key);
    XOR_Two(result, result, c, bk, key);
    XOR_Two(result, result, d, bk, key);
}

void MakeSBoxTable(LweSample **table, TFheGateBootstrappingParameterSet *params,
                   TFheGateBootstrappingSecretKeySet *key)
{
    int Sbox_binary[256][8];
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            //对SboxTable行循环,把每个十六进制转化为二进制数组
            int bin_str[8];
            HexToBinStr(SboxTable[i][j], bin_str);
            for (int k = 0; k < 8; k++)
            {
                Sbox_binary[i * 16 + j][k] = bin_str[k];
                // cout<< Sbox_binary[i*16+j][k] << " ";
            }
            // cout << endl;
        }
    }

    //make Sbox table: 256 * 8
    for (int j = 0; j < 8; j++)
    {
        table[j] = new_gate_bootstrapping_ciphertext_array(256, params);
        for (int i = 0; i < 256; i++)
        {
            bootsSymEncrypt(table[j] + i, Sbox_binary[i][j], key);
        }
    }
}

//查表函数 //256->128->64->32->16->8-> 4 -> 2 -> 1
void LookupTable(LweSample *result, LweSample *X, LweSample *table,
                 TFheGateBootstrappingParameterSet *params,
                 const TFheGateBootstrappingCloudKeySet *bk,
                 TFheGateBootstrappingSecretKeySet *key)

{
    //使用x0查表
    LweSample *ct128 = new_gate_bootstrapping_ciphertext_array(128, params);
    for (int i = 0; i < 128; i++)
    {
        bootsMUX(ct128 + i, X + 0, table + 2 * i + 1, table + 2 * i, bk);
    }

    //使用x1查表
    LweSample *ct64 = new_gate_bootstrapping_ciphertext_array(64, params);
    for (int i = 0; i < 64; i++)
    {
        bootsMUX(ct64 + i, X + 1, ct128 + 2 * i + 1, ct128 + 2 * i, bk);
    }

    //使用x2查表
    LweSample *ct32 = new_gate_bootstrapping_ciphertext_array(32, params);
    for (int i = 0; i < 32; i++)
    {
        bootsMUX(ct32 + i, X + 2, ct64 + 2 * i + 1, ct64 + 2 * i, bk);
    }
    //使用x3查表
    LweSample *ct16 = new_gate_bootstrapping_ciphertext_array(16, params);
    for (int i = 0; i < 16; i++)
    {
        bootsMUX(ct16 + i, X + 3, ct32 + 2 * i + 1, ct32 + 2 * i, bk);
    }

    //使用x4查表
    LweSample *ct8 = new_gate_bootstrapping_ciphertext_array(8, params);
    for (int i = 0; i < 8; i++)
    {
        bootsMUX(ct8 + i, X + 4, ct16 + 2 * i + 1, ct16 + 2 * i, bk);
    }

    //使用x5查表
    LweSample *ct4 = new_gate_bootstrapping_ciphertext_array(4, params);
    for (int i = 0; i < 4; i++)
    {
        bootsMUX(ct4 + i, X + 5, ct8 + 2 * i + 1, ct8 + 2 * i, bk);
    }

    //使用x6查表
    LweSample *ct2 = new_gate_bootstrapping_ciphertext_array(2, params);
    for (int i = 0; i < 2; i++)
    {
        bootsMUX(ct2 + i, X + 6, ct4 + 2 * i + 1, ct4 + 2 * i, bk);
    }
    //使用x7查表 找到结果
    bootsMUX(result, X + 7, ct2 + 1, ct2 + 0, bk);

#if 0
    // table 当前列
    for (int i = 0; i < 256; i++)
    {
        cout << bootsSymDecrypt(table + i, key) << " ";
    }
    cout << endl;
    //使用x0查表结果
    cout << "x0: " << bootsSymDecrypt(X + 0, key) << endl;
    for (int i = 0; i < 128; i++)
    {
        cout << bootsSymDecrypt(ct128 + i, key) << " ";
    }
    cout << endl;
    //使用x1查表结果
    cout << "x1: " << bootsSymDecrypt(X + 1, key) << endl;
    for (int i = 0; i < 64; i++)
    {
        cout << bootsSymDecrypt(ct64 + i, key) << " ";
    }
    cout << endl;
    //使用x2查表结果
    cout << "x2: " << bootsSymDecrypt(X + 2, key) << endl;
    for (int i = 0; i < 32; i++)
    {
        cout << bootsSymDecrypt(ct32 + i, key) << " ";
    }
    cout << endl;
    //使用x3查表结果
    cout << "x3: " << bootsSymDecrypt(X + 3, key) << endl;
    for (int i = 0; i < 16; i++)
    {
        cout << bootsSymDecrypt(ct16 + i, key) << " ";
    }
    cout << endl;
    //使用x4查表结果
    cout << "x4: " << bootsSymDecrypt(X + 4, key) << endl;
    for (int i = 0; i < 8; i++)
    {
        cout << bootsSymDecrypt(ct8 + i, key) << " ";
    }
    cout << endl;
    //使用x5查表结果
    cout << "x5: " << bootsSymDecrypt(X + 5, key) << endl;
    for (int i = 0; i < 4; i++)
    {
        cout << bootsSymDecrypt(ct4 + i, key) << " ";
    }
    cout << endl;
    //使用x6查表结果
    cout << "x6: " << bootsSymDecrypt(X + 6, key) << endl;
    for (int i = 0; i < 2; i++)
    {
        cout << bootsSymDecrypt(ct2 + i, key) << " ";
    }
    cout << endl;
    //使用x7查表 找到结果
    cout << "x7: " << bootsSymDecrypt(X + 7, key) << endl;
    cout << "当前列的查找结果： " << bootsSymDecrypt(result, key) << " ";
    cout << endl;
#endif

    delete_gate_bootstrapping_ciphertext_array(128, ct128);
    delete_gate_bootstrapping_ciphertext_array(64, ct64);
    delete_gate_bootstrapping_ciphertext_array(32, ct32);
    delete_gate_bootstrapping_ciphertext_array(16, ct16);
    delete_gate_bootstrapping_ciphertext_array(8, ct8);
    delete_gate_bootstrapping_ciphertext_array(4, ct4);
    delete_gate_bootstrapping_ciphertext_array(2, ct2);
}

void CipherAddRoundKey(LweSample **cipher, LweSample **rk, int round,
                       const TFheGateBootstrappingCloudKeySet *bk, TFheGateBootstrappingSecretKeySet *key)
{
    cout << "============密钥加============ " << endl;
    for (int i = 0; i < 16; i++)
    {
        XOR_Two(cipher[i], cipher[i], rk[round * 16 + i], bk, key);
    }
}

void CipherSubBytes(LweSample **B, LweSample **cipher, LweSample **Table, TFheGateBootstrappingParameterSet *params,
                    const TFheGateBootstrappingCloudKeySet *bk, TFheGateBootstrappingSecretKeySet *key)
{
    cout << "============字节替换============= " << endl;
    // LweSample *B[16];
    for (int i = 0; i < 16; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            // 比如使用X[0](8个bit) 查找某列Table[i],结果存在result+i
            LookupTable(B[i] + j, cipher[i], Table[j], params, bk, key);
        }
    }

#if 0
    //验证SM4的S盒输出
    for (int i = 0; i < 16; i++)
    {
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(B[i] + j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";
    }
    cout << endl;
#endif

    // //复制到cipher
    // for (int i = 0; i < 16; i++)
    // {
    //     for (int j = 0; j < 8; j++)
    //     {
    //         lweClear(cipher[i]+j, params->in_out_params);
    //         lweCopy(cipher[i]+j, B[i]+j, params->in_out_params);
    //     }
    // }
}
void CipherShiftRows(LweSample **cipher, LweSample **B, TFheGateBootstrappingParameterSet *params,
                     const TFheGateBootstrappingCloudKeySet *bk, TFheGateBootstrappingSecretKeySet *key)
{
    cout << "==============行移位==============" << endl;
    //  0  4  8  12                 \    0  4  8  12
    //  1  5  9  13           =======\   5  9  13 1
    //  2  6  10 14           ======-/   10 14 2  6
    //  3  7  11 15                 /    15 3  7  11
    //重新赋值Cipher
    for (int i = 0; i < 8; i++)
    {
        lweCopy(cipher[0] + i, B[0] + i, params->in_out_params);
        lweCopy(cipher[1] + i, B[5] + i, params->in_out_params);
        lweCopy(cipher[2] + i, B[10] + i, params->in_out_params);
        lweCopy(cipher[3] + i, B[15] + i, params->in_out_params);

        lweCopy(cipher[4] + i, B[4] + i, params->in_out_params);
        lweCopy(cipher[5] + i, B[9] + i, params->in_out_params);
        lweCopy(cipher[6] + i, B[14] + i, params->in_out_params);
        lweCopy(cipher[7] + i, B[3] + i, params->in_out_params);

        lweCopy(cipher[8] + i, B[8] + i, params->in_out_params);
        lweCopy(cipher[9] + i, B[13] + i, params->in_out_params);
        lweCopy(cipher[10] + i, B[2] + i, params->in_out_params);
        lweCopy(cipher[11] + i, B[7] + i, params->in_out_params);

        lweCopy(cipher[12] + i, B[12] + i, params->in_out_params);
        lweCopy(cipher[13] + i, B[1] + i, params->in_out_params);
        lweCopy(cipher[14] + i, B[6] + i, params->in_out_params);
        lweCopy(cipher[15] + i, B[11] + i, params->in_out_params);
    }
}

void CipherMul2(LweSample *byte, LweSample *consByte, TFheGateBootstrappingParameterSet *params,
                const TFheGateBootstrappingCloudKeySet *bk, TFheGateBootstrappingSecretKeySet *key)
{
    //Function: to  implement  byte times x mod f(x)

    LweSample *temp1 = new_LweSample_array(8, params->in_out_params);
    LweSample *temp2 = new_LweSample_array(8, params->in_out_params);

    LweSample *temp = new_LweSample(params->in_out_params);
    lweCopy(temp, byte + 7, params->in_out_params);

    for (int i = 1; i < 8; i++)
    {
        //移位
        lweCopy(temp1 + i, byte + i - 1, params->in_out_params);
    }
    lweCopy(temp1 + 0, temp, params->in_out_params);
    
    for (int i = 0; i < 8; i++)
    {
        bootsSymEncrypt(temp2 + i, 0, key);
        // lweCopy(temp2 + i, consByte+i, params->in_out_params);
        // lweClear(temp2+i,params->in_out_params);//error
        if (i == 1 || i == 3 || i == 4)
        {
            lweCopy(temp2 + i, temp, params->in_out_params);
        }
    }
    XOR_Two(byte, temp1, temp2, bk, key);

    delete_gate_bootstrapping_ciphertext_array(8, temp1);
    delete_gate_bootstrapping_ciphertext_array(8, temp2);
    delete_gate_bootstrapping_ciphertext(temp);
}

void CipherMulOriginal2(LweSample *byte, LweSample *consByte, TFheGateBootstrappingParameterSet *params,
                        const TFheGateBootstrappingCloudKeySet *bk, TFheGateBootstrappingSecretKeySet *key)
{
    //Function: to  implement  byte times x mod f(x)
    //选择bit
    LweSample *selectbit = new_LweSample(params->in_out_params);
    lweCopy(selectbit, byte + 7, params->in_out_params);

    LweSample *temp1 = new_LweSample_array(8, params->in_out_params);
    LweSample *temp2 = new_LweSample_array(8, params->in_out_params);

    bootsSymEncrypt(temp1 + 0, 0, key); //低位置0

    for (int i = 1; i < 8; i++)
    {
        //移位
        lweCopy(temp1 + i, byte + i - 1, params->in_out_params);
    }

    XOR_Two(temp2, temp1, consByte, bk, key);

    // a7 = 0选择temp1, a7 = 1 选择temp2
    for (int i = 0; i < 8; i++)
    {
        bootsMUX(byte + i, selectbit, temp2 + i, temp1 + i, bk);
    }
    delete_gate_bootstrapping_ciphertext_array(8, temp1);
    delete_gate_bootstrapping_ciphertext_array(8, temp2);
}

void CipherMixColumns(LweSample **cipher, LweSample *consByte, TFheGateBootstrappingParameterSet *params,
                      const TFheGateBootstrappingCloudKeySet *bk, TFheGateBootstrappingSecretKeySet *key)
{
    cout << "==============列混淆==============" << endl;
    //
    // [02  03  01  01] [ s00  s01  s02  s03]
    // |01  02  03  01| | s10  s11  s12  s13|
    // |01  01  02  03| | s20  s21  s22  s23|
    // [03  01  01  02] [ s30  s31  s32  s33]

    // 构造乘以 2的函数
    for (int i = 0; i < 4; i++)
    {
        LweSample *t = new_LweSample_array(8, params->in_out_params);
        LweSample *Tmp = new_LweSample_array(8, params->in_out_params);
        LweSample *Tm = new_LweSample_array(8, params->in_out_params);

        for (int j = 0; j < 8; j++)
        {
            lweCopy(t + j, cipher[4 * i + 0] + j, params->in_out_params); // t = cipher[0][i]
        }

        //Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];  //四个异或值为6
        XOR_Four(Tmp, cipher[4 * i + 0], cipher[4 * i + 1], cipher[4 * i + 2], cipher[4 * i + 3], bk, key);

        //Tm = state[0][i] ^ state[1][i];
        for (int j = 0; j < 8; j++)
        {
            lweCopy(Tm + j, cipher[4 * i + 0] + j, params->in_out_params); // t = cipher[0][i]
        }
        XOR_Two(Tm, Tm, cipher[4 * i + 1], bk, key);

#if 0
        cout << "=============验证XOR_Two确性============" << endl;
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(Tm+ j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";

        cout << endl;
        return ;

#endif
        //Tm = xtime(Tm)   // 6b->d6
        CipherMul2(Tm, consByte, params, bk, key);
#if 0
        cout << "=============验证GFmul2正确性============" << endl;
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(Tm + j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";

        cout << endl;
        return;

#endif

        //state[0][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 0], cipher[4 * i + 0], Tm, bk, key);  //2
        XOR_Two(cipher[4 * i + 0], cipher[4 * i + 0], Tmp, bk, key); //4

#if 0
        // cout << "=============验证正确性============" << endl;
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(cipher[4 * i + 0] + j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";
#endif

        //========================================================================================
        //  Tm = state[1][i] ^ state[2][i];
        for (int j = 0; j < 8; j++)
        {
            lweCopy(Tm + j, cipher[4 * i + 1] + j, params->in_out_params);
        }
        XOR_Two(Tm, Tm, cipher[4 * i + 2], bk, key);
        //  Tm = xtime(Tm);
        CipherMul2(Tm, consByte, params, bk, key);
        // state[1][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 1], cipher[4 * i + 1], Tm, bk, key);
        XOR_Two(cipher[4 * i + 1], cipher[4 * i + 1], Tmp, bk, key);

        //=========================================================================================
        // Tm = state[2][i] ^ state[3][i];
        for (int j = 0; j < 8; j++)
        {
            lweCopy(Tm + j, cipher[4 * i + 2] + j, params->in_out_params);
        }
        XOR_Two(Tm, Tm, cipher[4 * i + 3], bk, key);
        // Tm = xtime(Tm);
        CipherMul2(Tm, consByte, params, bk, key);
        // state[2][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 2], cipher[4 * i + 2], Tm, bk, key);
        XOR_Two(cipher[4 * i + 2], cipher[4 * i + 2], Tmp, bk, key);

        //=========================================================================================
        // Tm = state[3][i] ^ t;
        for (int j = 0; j < 8; j++)
        {
            lweCopy(Tm + j, cipher[4 * i + 3] + j, params->in_out_params);
        }
        XOR_Two(Tm, Tm, t, bk, key);

        // Tm = xtime(Tm);
        CipherMul2(Tm, consByte, params, bk, key);
        // state[3][i] ^= Tm ^ Tmp;
        XOR_Two(cipher[4 * i + 3], cipher[4 * i + 3], Tm, bk, key);
        XOR_Two(cipher[4 * i + 3], cipher[4 * i + 3], Tmp, bk, key);

        delete_gate_bootstrapping_ciphertext_array(8, t);
        delete_gate_bootstrapping_ciphertext_array(8, Tmp);
        delete_gate_bootstrapping_ciphertext_array(8, Tm);
    }
}

int main01()
{
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {214, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *key = new_random_gate_bootstrapping_secret_keyset(params);

    const TFheGateBootstrappingCloudKeySet *bk = &(key->cloud);

    int a[8] = {0, 1, 1, 0, 1, 0, 1, 0};
    LweSample *X = new_LweSample_array(8, params->in_out_params);
    LweSample *consByte = new_LweSample_array(8, params->in_out_params);
    for (int i = 0; i < 8; i++)
    {
        // 常量异或
        bootsSymEncrypt(consByte + i, byte_mul2[i], key);
    }
    for (int i = 0; i < 8; i++)
    {
        bootsSymEncrypt(X + i, a[i], key);
    }

    for (size_t i = 0; i < 8; i++)
    {
        cout << bootsSymDecrypt(X + i, key) << " ";
    }

    cout << endl;

    CipherMul2(X, consByte, params, bk, key);

    for (size_t i = 0; i < 8; i++)
    {
        cout << bootsSymDecrypt(X + i, key) << " ";
    }
    cout << endl;
    return 0;
}
int main()
{
    const int minimum_lambda = 110;
    TFheGateBootstrappingParameterSet *params = new_default_gate_bootstrapping_parameters(minimum_lambda);

    //generate a random key
    uint32_t seed[] = {214, 1592, 657};
    tfhe_random_generator_setSeed(seed, 3);
    TFheGateBootstrappingSecretKeySet *key = new_random_gate_bootstrapping_secret_keyset(params);

    const TFheGateBootstrappingCloudKeySet *bk = &(key->cloud);

    int columns = 8;
    LweSample *Table[columns]; //使用指针数组

    cout << " ===============  开始制作SBox表格=============" << endl;
    clock_t make_begin = clock();
    MakeSBoxTable(Table, params, key);
    clock_t make_end = clock();
    double total_time_maketable = 0.0;
    total_time_maketable = make_end - make_end;
    cout << "total_time_maketable:  " << total_time_maketable << endl;

#if 0
    //对表格解密看看 
    cout<<"================"<<endl;
    for (int i = 0; i < 256; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            cout<< bootsSymDecrypt(Table[j]+i, key)<< " ";
        }
        cout<< endl;
    }

    return 0;
#endif

    //定义一个初始的布尔值输入数组128 bit，然后加密输入
    // plain: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
    // key:   01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10

    unsigned char plain[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                               0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    unsigned char aeskey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

    LweSample *consByte = new_LweSample_array(8, params->in_out_params);
    for (int i = 0; i < 8; i++)
    {
        // 常量异或
        bootsSymEncrypt(consByte + i, byte_mul2[i], key);
    }

    cout << " .........生成SM4的轮密钥........" << endl;
    // Compute the key expansion
    unsigned char RoundKey[240];
    long nRoundKeys = AESKeyExpansion(RoundKey, aeskey, 128);
    cout << " 轮数： " << nRoundKeys << endl;

    //定义输入的指针数组
    LweSample **cipher = new LweSample *[16];
    // 输入加密 16 * 8 bit
    for (int i = 0; i < 16; i++)
    {
        cipher[i] = new_gate_bootstrapping_ciphertext_array(8, params); // 8bit
        int bin_str[8];
        HexToBinStr(plain[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            //  cout << bin_str[j]<<" ";
            bootsSymEncrypt(cipher[i] + j, bin_str[j], key); //对X1的每个比特进行加密
        }
        // cout <<endl;
    }
#if 1
    cout << " 验证输入明文加密的正确性....." << endl;
    for (int i = 0; i < 16; i++)
    {
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(cipher[i] + j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";
    }
    cout << endl;
#endif

    // 11轮密钥加密
    LweSample **rk = new LweSample *[240];
    for (int i = 0; i < 240; i++)
    {
        int bin_str[8];
        HexToBinStr(RoundKey[i], bin_str);
        rk[i] = new_gate_bootstrapping_ciphertext_array(8, params);
        for (int j = 0; j < 8; j++)
        {
            // cout << bin_str[k] << " ";
            bootsSymEncrypt(&rk[i][j], bin_str[j], key);
        }
    }

#if 0
    cout << " 验证AES扩展密钥加密的正确性....." << endl;
    for (int i = 0; i < 80; i++)
    {
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(rk[i] + j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";
    }
    cout << endl;
#endif

    //==================AES的加密步骤==================================
    //初始轮数 ：加轮密钥
    // 轮函数：
    //1-9轮： 字节替换： 行移位、 列混淆、轮密钥
    // 第10轮：  字节替换： 行移位、轮密钥

    CipherAddRoundKey(cipher, rk, 0, bk, key);
#if 0
    cout << "=============验证第0轮密钥加法的正确性============" << endl;
    for (int i = 0; i < 16; i++)
    {
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(cipher[i] + j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";
    }
    cout << endl;
#endif

    // 接下里9轮函数
    LweSample *B[16];
    for (int i = 0; i < 16; i++)
    {
        B[i] = new_gate_bootstrapping_ciphertext_array(8, params);
    }

    for (int i = 1; i < 10; i++)
    {
        cout << "================第 " << i << "轮==================" << endl;
        clock_t look_begin = clock();
        CipherSubBytes(B, cipher, Table, params, bk, key);
        clock_t look_end = clock();
        double total_time_look = 0.0;
        total_time_look = look_end - look_begin;
        cout << "字节代换的时间:  " << total_time_look * clocks2seconds << " s......." << endl;

#if 1
        cout << "=============验证字节代换的正确性============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_bin[8];
            int dec_result = 0;
            for (int j = 0; j < 8; j++)
            {
                dec_bin[j] = bootsSymDecrypt(B[i] + j, key);
            }
            BinStrToHex(dec_result, dec_bin);
            cout << hex << dec_result << " ";
        }
        cout << endl;
#endif

        CipherShiftRows(cipher, B, params, bk, key);
#if 1
        cout << "=============验证行移位的正确性============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_bin[8];
            int dec_result = 0;
            for (int j = 0; j < 8; j++)
            {
                dec_bin[j] = bootsSymDecrypt(cipher[i] + j, key);
            }
            BinStrToHex(dec_result, dec_bin);
            cout << hex << dec_result << " ";
        }
        cout << endl;
#endif

        /*
    unsigned char test[16] = {0xd4, 0xbf, 0x5d, 0x30, 0xe0, 0xb4, 0x52, 0xae,
                              0xb8, 0x41, 0x11, 0xf1, 0x1e, 0x27, 0x98, 0xe5};
    LweSample **cipher = new LweSample *[16];
    // 输入加密 16 * 8 bit
    for (int i = 0; i < 16; i++)
    {
        cipher[i] = new_gate_bootstrapping_ciphertext_array(8, params); // 8bit
        int bin_str[8];
        HexToBinStr(test[i], bin_str);
        for (int j = 0; j < 8; j++)
        {
            //  cout << bin_str[j]<<" ";
            bootsSymEncrypt(cipher[i] + j, bin_str[j], key); //对X1的每个比特进行加密
        }
        // cout <<endl;
    }
#if 1
    cout << " 验证测试明文加密的正确性....." << endl;
    for (int i = 0; i < 16; i++)
    {
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(cipher[i] + j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";
    }
    cout << endl;
#endif
*/
        CipherMixColumns(cipher, consByte, params, bk, key);
#if 1
        cout << "=============验证列混淆的正确性============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_bin[8];
            int dec_result = 0;
            for (int j = 0; j < 8; j++)
            {
                dec_bin[j] = bootsSymDecrypt(cipher[i] + j, key);
            }
            BinStrToHex(dec_result, dec_bin);
            cout << hex << dec_result << " ";
        }
        cout << endl;
#endif

        CipherAddRoundKey(cipher, rk, i, bk, key);
#if 1
        cout << "=============验证第 " << i << " 轮密钥加法的正确性============" << endl;
        for (int i = 0; i < 16; i++)
        {
            int dec_bin[8];
            int dec_result = 0;
            for (int j = 0; j < 8; j++)
            {
                dec_bin[j] = bootsSymDecrypt(cipher[i] + j, key);
            }
            BinStrToHex(dec_result, dec_bin);
            cout << hex << dec_result << " ";
        }
        cout << endl;
#endif
    }
    // 最后三个操作................................
    cout << "================第 " << 10 << " 轮==================" << endl;
    clock_t look_begin = clock();
    CipherSubBytes(B, cipher, Table, params, bk, key);
    clock_t look_end = clock();
    double total_time_look = 0.0;
    total_time_look = look_end - look_begin;
    cout << "字节代换的时间:  " << total_time_look * clocks2seconds << " s......." << endl;

#if 1
    cout << "=============验证字节代换的正确性============" << endl;
    for (int i = 0; i < 16; i++)
    {
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(B[i] + j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";
    }
    cout << endl;
#endif

    CipherShiftRows(cipher, B, params, bk, key);
#if 1
    cout << "=============验证行移位的正确性============" << endl;
    for (int i = 0; i < 16; i++)
    {
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(cipher[i] + j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";
    }
    cout << endl;
#endif
    CipherAddRoundKey(cipher, rk, 10, bk, key);
#if 1
    cout << "=============验证最后结果的正确性============" << endl;
    for (int i = 0; i < 16; i++)
    {
        int dec_bin[8];
        int dec_result = 0;
        for (int j = 0; j < 8; j++)
        {
            dec_bin[j] = bootsSymDecrypt(cipher[i] + j, key);
        }
        BinStrToHex(dec_result, dec_bin);
        cout << hex << dec_result << " ";
    }
    cout << endl;
#endif
    return 0;
}
