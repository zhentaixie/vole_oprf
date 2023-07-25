#include "../okvs3/Baxos.h"
#include "coproto/coproto.h"
#include "coproto/Socket/AsioSocket.h"
#include "libOTe/Vole/Silent/SilentVoleReceiver.h"
#include "libOTe/Vole/Silent/SilentVoleSender.h"
#include <omp.h>
#include <iostream>
#include <vector>
#include "../netio/stream_channel.hpp"
#include "../utility/print.hpp"
#include "../crypto/block.hpp"

namespace VOLEOPRF
{
    struct PP
    {
        size_t LEN; // the length of the client's input vector

        size_t okvs_bin_size;    // the bin size in multi-threaded OKVS
        Baxos<gf_128> okvs;      // OKVS object
        size_t okvs_output_size; // the size of the output vector obtained in the OKVS encoding process

        // a common PRG seed, used to generate some random blocks
        PRG::Seed common_seed;

        bool is_malicious;

        // the data that needs to be saved during the interaction for the Evaluate evaluation
        block Delta;
        block W;

        size_t thread_num;
    };

    PP Setup(size_t LOG_LEN, size_t statistical_security_parameter = 40)
    {
        PP pp;
        pp.LEN = 1ull << LOG_LEN; // LEN = 2^{LOG_LEN}

        pp.okvs_bin_size = 1ull << 15;
        pp.okvs = Baxos<gf_128>(pp.LEN, pp.okvs_bin_size, 3, statistical_security_parameter);
        pp.okvs_output_size = pp.okvs.bin_num * pp.okvs.total_size;

        pp.common_seed = PRG::SetSeed(fixed_seed, 0);

        pp.is_malicious = true;

        pp.thread_num = omp_get_max_threads();
        return pp;
    }
    std::vector<block> Client(NetIO &io, PP &pp, std::vector<block> &vec_Y, size_t ITEM_NUM)
    {
        PrintSplitLine('-');
        auto start_time = std::chrono::steady_clock::now();

        // because the VOLE interface in libOTe only accepts Socket objects, we need to build the chl
        auto chl = coproto::asioConnect("localhost:1212", false);
        bool is_malicious = pp.is_malicious;

        // the seed used to generate the initial random data
        auto prng_seed = Block::zero_block;
        PRG::Seed seed = PRG::SetSeed((const void *)&prng_seed, 0);

        // Fig 4.Step 1:the receiver receives c_s
        std::array<block, 2> H_ws;
        osuCrypto::SilentVoleReceiver receiver;
        if (is_malicious)
        {
            receiver.mMalType = oc::SilentSecType::Malicious;
            io.ReceiveBlocks(H_ws.data(), 2);
        }

        // Fig 4.Step 2:Sample r,w_r
        auto random_blocks = PRG::GenRandomBlocks(seed, 2);
        block seed_r = std::move(random_blocks[0]);
        block w_r = std::move(random_blocks[1]);

        PRG::Seed okvs_seed = PRG::SetSeed(&seed_r, 0);
        pp.okvs.seed = okvs_seed;

        // Fig 4.Step 2:the receiver solves the systems
        auto size = pp.okvs_output_size;
        std::vector<block> hashed_vec_Y(ITEM_NUM);
        auto hash_key = pp.common_seed.aes_key;
        AES::FastECBEnc(hash_key, vec_Y.data(), ITEM_NUM, hashed_vec_Y.data());

        std::vector<block> P(size);
        pp.okvs.solve(vec_Y, hashed_vec_Y, P, nullptr, pp.thread_num);

        // Fig 4.Step 3:VOLE
        osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
        std::vector<osuCrypto::block> A(size);
        std::vector<block> C(size);
        auto A_span = osuCrypto::span<osuCrypto::block>(A.data(), size);
        auto C_span = osuCrypto::span<osuCrypto::block>((osuCrypto::block *)C.data(), size);
        auto p0 = receiver.silentReceive(A_span, C_span, prng, chl);
        coproto::sync_wait(p0);
        coproto::sync_wait(chl.flush());

        // Fig 4.Step 4:send r
        io.SendBlock(seed_r);

        block w_s;
        if (is_malicious)
        {
            // Fig 4.Step 4:the receiver sends w_r
            io.SendBlock(w_r);
            // Fig 4.Step 5:the receiver receives w_s
            io.ReceiveBlock(w_s);
        }
        uint64_t i = 0;
        for (; i + 8 <= size; i += 8)
        {
            P[i] ^= A[i].mData;
            P[i + 1] ^= A[i + 1].mData;
            P[i + 2] ^= A[i + 2].mData;
            P[i + 3] ^= A[i + 3].mData;
            P[i + 4] ^= A[i + 4].mData;
            P[i + 5] ^= A[i + 5].mData;
            P[i + 6] ^= A[i + 6].mData;
            P[i + 7] ^= A[i + 7].mData;
        }
        for (; i < size; i++)
        {
            P[i] ^= A[i].mData;
        }

        // Fig 4.Step 4:send A=P+A'
        io.SendBlocks(P.data(), P.size());

        // Prepare for Fig 4.Step 6 Decode(C,x)
        std::vector<block> output(ITEM_NUM);
        pp.okvs.decode(vec_Y, output, C, pp.thread_num);

        if (is_malicious)
        {
            // Fig 4.Step 5:receiver receives H_ws and compare
            block H_ws_2[2];
            BasicHash((unsigned char *)(&w_s), sizeof(block), (unsigned char *)(H_ws_2));
            if (memcmp(&H_ws_2, &H_ws, sizeof(block) * 2))
                throw;
            auto W = w_s ^ w_r;

            // Fig 4.Step 6:Compute X'=Fk_X
            uint64_t i = 0;
            for (; i + 8 <= ITEM_NUM; i += 8)
            {
                output[i] ^= W;
                output[i + 1] ^= W;
                output[i + 2] ^= W;
                output[i + 3] ^= W;
                output[i + 4] ^= W;
                output[i + 5] ^= W;
                output[i + 6] ^= W;
                output[i + 7] ^= W;

                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i], 0).aes_key, &vec_Y[i], 1, &output[i]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 1], 0).aes_key, &vec_Y[i + 1], 1, &output[i + 1]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 2], 0).aes_key, &vec_Y[i + 2], 1, &output[i + 2]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 3], 0).aes_key, &vec_Y[i + 3], 1, &output[i + 3]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 4], 0).aes_key, &vec_Y[i + 4], 1, &output[i + 4]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 5], 0).aes_key, &vec_Y[i + 5], 1, &output[i + 5]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 6], 0).aes_key, &vec_Y[i + 6], 1, &output[i + 6]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 7], 0).aes_key, &vec_Y[i + 7], 1, &output[i + 7]);

                output[i] ^= vec_Y[i];
                output[i + 1] ^= vec_Y[i + 1];
                output[i + 2] ^= vec_Y[i + 2];
                output[i + 3] ^= vec_Y[i + 3];
                output[i + 4] ^= vec_Y[i + 4];
                output[i + 4] ^= vec_Y[i + 4];
                output[i + 5] ^= vec_Y[i + 5];
                output[i + 6] ^= vec_Y[i + 6];
                output[i + 7] ^= vec_Y[i + 7];
            }
            for (; i < ITEM_NUM; i++)
            {
                output[i] ^= W;
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i], 0).aes_key, &vec_Y[i], 1, &output[i]);
                output[i] ^= vec_Y[i];
            }
        }
        else
        {
            auto key = pp.common_seed.aes_key;
            std::vector<block> output_(output.size());
            AES::FastECBEnc(key, output.data(), ITEM_NUM, output_.data());
            uint64_t i = 0;
            for (; i + 8 <= ITEM_NUM; i += 8)
            {
                output[i] ^= output_[i];
                output[i + 1] ^= output_[i + 1];
                output[i + 2] ^= output_[i + 2];
                output[i + 3] ^= output_[i + 3];
                output[i + 4] ^= output_[i + 4];
                output[i + 5] ^= output_[i + 5];
                output[i + 6] ^= output_[i + 6];
                output[i + 7] ^= output_[i + 7];
            }
            for (; i < ITEM_NUM; i++)
            {
                output[i] ^= output_[i];
            }
        }
        auto end_time = std::chrono::steady_clock::now();
        auto running_time = end_time - start_time;
        std::cout << "VOLE-based OPRF: Client side takes time = "
                  << std::chrono::duration<double, std::milli>(running_time).count() << " ms" << std::endl;
        PrintSplitLine('-');
        return output;
    }

    std::vector<block> Server(NetIO &io, PP &pp)
    {
        PrintSplitLine('-');
        auto start_time = std::chrono::steady_clock::now();

        // because the VOLE interface in libOTe only accepts Socket objects, we need to build the chl
        auto chl = coproto::asioConnect("localhost:1212", true);
        bool is_malicious = pp.is_malicious;

        // the seed used to generate the initial random data
        auto prng_seed = Block::MakeBlock(0, 1);
        PRG::Seed seed = PRG::SetSeed((const void *)&prng_seed, 0);
        auto random_blocks = PRG::GenRandomBlocks(seed, 2);

        // Fig.4 Step 1:the Sender samples ws ← F
        block w_s = random_blocks[0];
        pp.Delta = random_blocks[1];

        osuCrypto::SilentVoleSender sender;
        sender.mNumThreads = pp.thread_num;

        if (is_malicious)
        {
            sender.mMalType = oc::SilentSecType::Malicious;
            // Fig 4. Step 1:the sender sends cs := H(ws) to the Receiver
            block cs[2];
            BasicHash((unsigned char *)(&w_s), sizeof(block), (unsigned char *)(&cs));
            io.SendBlocks(cs, 2);
        }

        auto size = pp.okvs_output_size;

        // Fig 4.Step 3:VOLE
        osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
        std::vector<block> K(size); // K=B
        auto K_span = osuCrypto::span<osuCrypto::block>((osuCrypto::block *)K.data(), size);
        auto p1 = sender.silentSend(*(osuCrypto::block *)(&pp.Delta), K_span, prng, chl);
        coproto::sync_wait(p1);
        coproto::sync_wait(chl.flush());

        // Fig 4.Step 4: the sender receives r
        block seed_r;
        io.ReceiveBlock(seed_r);

        PRG::Seed okvs_seed = PRG::SetSeed(&seed_r, 0);
        pp.okvs.seed = okvs_seed;

        block *K_pointer = K.data();
        // receive w_r,and compute w = w_r^w_s
        if (is_malicious)
        {
            // Fig 4.Step 4: the sender receives w_r
            io.ReceiveBlock(pp.W);
            // Fig 4.Step 5: the sender sends w_s
            io.SendBlock(w_s);
            pp.W ^= w_s;
        }

        // Fig 4.Step 4: the sender receives A
        auto A = std::vector<block>(size);
        auto P_pointer = A.data();
        io.ReceiveBlocks(P_pointer, size);

        // Fig 4.Step 4: the sender computes K=B+A*Delta
        uint64_t i = 0;
        auto Delta = pp.Delta;
        for (; i + 8 <= size; i += 8, K_pointer += 8, P_pointer += 8)
        {
            K_pointer[0] ^= gf128_mul(Delta, P_pointer[0]);
            K_pointer[1] ^= gf128_mul(Delta, P_pointer[1]);
            K_pointer[2] ^= gf128_mul(Delta, P_pointer[2]);
            K_pointer[3] ^= gf128_mul(Delta, P_pointer[3]);
            K_pointer[4] ^= gf128_mul(Delta, P_pointer[4]);
            K_pointer[5] ^= gf128_mul(Delta, P_pointer[5]);
            K_pointer[6] ^= gf128_mul(Delta, P_pointer[6]);
            K_pointer[7] ^= gf128_mul(Delta, P_pointer[7]);
        }
        for (; i < size; i++, K_pointer++, P_pointer++)
        {
            *K_pointer ^= gf128_mul(Delta, *P_pointer);
        }

        auto end_time = std::chrono::steady_clock::now();
        auto running_time = end_time - start_time;
        std::cout << "VOLE-based OPRF: Server side takes time = "
                  << std::chrono::duration<double, std::milli>(running_time).count() << " ms" << std::endl;
        PrintSplitLine('-');
        return K;
    }

    std::vector<block> Evaluate(PP &pp, std::vector<block> &oprf_key, std::vector<block> &vec_X, size_t ITEM_NUM)
    {
        bool is_malicious = pp.is_malicious;
        block Delta = pp.Delta;
        block W = pp.W;
        // The last sentence in Fig 4
        // Compute F(y)=H(Decode(K, y) − Delta*H(y) + w,y)
        std::vector<block> output(ITEM_NUM);
        std::vector<block> hashed_vec_X(ITEM_NUM);
        auto hash_key = pp.common_seed.aes_key;
        AES::FastECBEnc(hash_key, vec_X.data(), ITEM_NUM, hashed_vec_X.data());

        pp.okvs.decode(vec_X, output, oprf_key, 1);
        std::cout << std::endl;
        // Block::PrintBlock(output[0]);
        std::cout << std::endl;
        if (is_malicious)
        {
            uint64_t i = 0;
            // #pragma omp parallel num_threads(pp.thread_num)
            //             uint8_t thread_id = omp_get_thread_num();
            //             uint64_t i = ITEM_NUM * thread_id / pp.thread_num;
            //             uint64_t item_num = ITEM_NUM * (thread_id + 1) / pp.thread_num - i;

            for (; i + 8 <= ITEM_NUM; i += 8)
            {
                output[i] ^= gf128_mul(Delta, hashed_vec_X[i]);
                output[i + 1] ^= gf128_mul(Delta, hashed_vec_X[i + 1]);
                output[i + 2] ^= gf128_mul(Delta, hashed_vec_X[i + 2]);
                output[i + 3] ^= gf128_mul(Delta, hashed_vec_X[i + 3]);
                output[i + 4] ^= gf128_mul(Delta, hashed_vec_X[i + 4]);
                output[i + 5] ^= gf128_mul(Delta, hashed_vec_X[i + 5]);
                output[i + 6] ^= gf128_mul(Delta, hashed_vec_X[i + 6]);
                output[i + 7] ^= gf128_mul(Delta, hashed_vec_X[i + 7]);

                output[i] ^= W;
                output[i + 1] ^= W;
                output[i + 2] ^= W;
                output[i + 3] ^= W;
                output[i + 4] ^= W;
                output[i + 5] ^= W;
                output[i + 6] ^= W;
                output[i + 7] ^= W;

                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i], 0).aes_key, &vec_X[i], 1, &output[i]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 1], 0).aes_key, &vec_X[i + 1], 1, &output[i + 1]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 2], 0).aes_key, &vec_X[i + 2], 1, &output[i + 2]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 3], 0).aes_key, &vec_X[i + 3], 1, &output[i + 3]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 4], 0).aes_key, &vec_X[i + 4], 1, &output[i + 4]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 5], 0).aes_key, &vec_X[i + 5], 1, &output[i + 5]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 6], 0).aes_key, &vec_X[i + 6], 1, &output[i + 6]);
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i + 7], 0).aes_key, &vec_X[i + 7], 1, &output[i + 7]);

                output[i] ^= vec_X[i];
                output[i + 1] ^= vec_X[i + 1];
                output[i + 2] ^= vec_X[i + 2];
                output[i + 3] ^= vec_X[i + 3];
                output[i + 4] ^= vec_X[i + 4];
                output[i + 4] ^= vec_X[i + 4];
                output[i + 5] ^= vec_X[i + 5];
                output[i + 6] ^= vec_X[i + 6];
                output[i + 7] ^= vec_X[i + 7];
            }
            for (; i < ITEM_NUM; i++)
            {
                output[i] ^= gf128_mul(Delta, hashed_vec_X[i]);
                output[i] ^= W;
                AES::FastECBEnc(PRG::SetSeed((const void *)&output[i], 0).aes_key, &vec_X[i], 1, &output[i]);
                output[i] ^= vec_X[i];
            }
        }
        else
        {
            auto key = pp.common_seed.aes_key;
            std::vector<block> output_(output.size());
            AES::FastECBEnc(key, output.data(), ITEM_NUM, output_.data());
            uint64_t i = 0;
            for (; i + 8 <= ITEM_NUM; i += 8)
            {
                output[i] ^= output_[i];
                output[i + 1] ^= output_[i + 1];
                output[i + 2] ^= output_[i + 2];
                output[i + 3] ^= output_[i + 3];
                output[i + 4] ^= output_[i + 4];
                output[i + 5] ^= output_[i + 5];
                output[i + 6] ^= output_[i + 6];
                output[i + 7] ^= output_[i + 7];
            }
            for (; i < ITEM_NUM; i++)
            {
                output[i] ^= output_[i];
            }
        }
        // for (auto ii = 0; ii < 8; ii++)
        //     Block::PrintBlock(output[ii]);
        return output;
    }

    // void Client2(NetIO &io)
    // {
    //     std::vector<block> a(1000, Block::all_one_block);
    //     for (auto i = 0; i < 100; i++)
    //     {
    //         io.SendBlocks(a.data(), 1000);
    //         io.ReceiveBlocks(a.data(), 1000);
    //     }
    // }
    // void Server2(NetIO &io)
    // {
    //     std::vector<block> a(1000);
    //     for (auto i = 0; i < 100; i++)
    //     {
    //         io.ReceiveBlocks(a.data(), 1000);
    //         io.SendBlocks(a.data(), 1000);
    //     }
    // }
}