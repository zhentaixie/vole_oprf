These files implement the oprf used in the paper <u>Blazing Fast PSI from Improved OKVS and Subfield VOLE</u> using Kunlun and libOTe. They reference the open-source implementation available at https://github.com/Visa-Research/volepsi. 

## libOTe

```
git clone --recursive https://github.com/osu-crypto/libOTe.git
cd libOTE
mkdir -p out/build/linux
cmake -S . -B out/build/linux -DENABLE_ASAN=ON -DFETCH_AUTO=ON -DENABLE_RELIC=ON -DENABLE_ALL_OT=ON -DENABLE_BOOST=ON -DENABLE_SILENT_VOLE=ON
cmake --build out/build/linux
```

If the following steps are omitted, the path of libOTe in CMakeLists.txt needs to be modified to be correct.

```
su (enter your password)
cmake --install out/build/linux 
```

## Kunlun

```
git clone https://github.com/yuchen1024/Kunlun
```

## oprf

Place the oprf folder in Kunlun, modify to ensure that the path of libOTe in CMakeLists and the header files of okvs are correct,

```
mkdir build
cd build
cmake ..
make
```

