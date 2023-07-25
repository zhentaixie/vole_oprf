#include "OPRF.h"
#include "../crypto/setup.hpp"

struct VOLEOPRFTestCase
{
    std::vector<block> vec_X; // server set
    std::vector<block> vec_Y; // client set
    size_t LEN;               // size of set
};

VOLEOPRFTestCase GenTestCase(size_t LOG_LEN)
{
    VOLEOPRFTestCase testcase;
    testcase.LEN = 1 << LOG_LEN;

    PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, testcase.LEN);

    return testcase;
}

void SaveTestCase(VOLEOPRFTestCase &testcase, std::string testcase_filename)
{
    std::ofstream fout;
    fout.open(testcase_filename, std::ios::binary);
    if (!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1);
    }
    fout << testcase.LEN;

    fout << testcase.vec_X;

    fout.close();
}

void FetchTestCase(VOLEOPRFTestCase &testcase, std::string testcase_filename)
{
    std::ifstream fin;
    fin.open(testcase_filename, std::ios::binary);
    if (!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1);
    }
    fin >> testcase.LEN;

    testcase.vec_X.resize(testcase.LEN);

    fin >> testcase.vec_X;

    fin.close();
}

int main()
{
    // CRYPTO_Initialize();

    // std::cout << "VOLE-based OPRF test begins >>>" << std::endl;

    // PrintSplitLine('-');
    // std::cout << "generate or load public parameters and test case" << std::endl;

    size_t LOG_LEN = 20;

    // generate pp (must be same for both server and client)
    // std::string pp_filename = "VOLEOPRF.pp";
    VOLEOPRF::PP pp;
    // if(!FileExist(pp_filename)){
    //     pp = VOLEOPRF::Setup(LOG_LEN); // 40 is the statistical parameter
    //     VOLEOPRF::SavePP(pp, pp_filename);
    // }
    // else{
    //     VOLEOPRF::FetchPP(pp, pp_filename);
    // }
    pp = VOLEOPRF::Setup(LOG_LEN); // 40 is the statistical parameter

    std::cout << "number of elements = " << (1 << LOG_LEN) << std::endl;

    std::string testcase_filename = "VOLEOPRF.testcase";

    VOLEOPRFTestCase testcase;
    // if(!FileExist(testcase_filename)){
    //     testcase = GenTestCase(LOG_LEN);
    //     SaveTestCase(testcase, testcase_filename);
    // }
    // else{
    //     FetchTestCase(testcase, testcase_filename);
    // }
    testcase = GenTestCase(LOG_LEN);
    PrintSplitLine('-');

    std::string party;
    std::cout << "please select your role between server and receiver (hint: first start server, then start client) ==> ";
    std::getline(std::cin, party);

    if (party == "server")
    {
        NetIO server_io("server", "", 8080);

        std::vector<block> oprf_key = VOLEOPRF::Server(server_io, pp);
        std::vector<block> vec_Fk_X = VOLEOPRF::Evaluate(pp, oprf_key, testcase.vec_X, pp.LEN);

        std::vector<block> vec(pp.LEN);
        server_io.ReceiveBlocks(vec.data(), vec.size());

        for (auto i = 0; i < pp.LEN; i++)
        {
            if (!Block::Compare(vec[i], vec_Fk_X[i]))
                throw;
        }
    }

    if (party == "client")
    {
        NetIO client_io("client", "127.0.0.1", 8080);
        std::vector<block> vec_Fk_X = VOLEOPRF::Client(client_io, pp, testcase.vec_X, pp.LEN);
        client_io.SendBlocks(vec_Fk_X.data(), vec_Fk_X.size());
    }

    // CRYPTO_Finalize();

    return 0;
}