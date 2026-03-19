## Compilation 

``` bash
make  
```

## Install
``` bash
make install
```

## Test libcaesar
``` bash
make test
```

## Usage
``` bash
./caesar <library.so> <key> <scr_file> <dst_file>
./secure_copy <file_1> ... <file_n> <output_dir> <key>
```
### Example
``` bash
./caesar ./libcaesar.so Y data/input.txt data/output.txt
./secure_copy data/file1.txt data/file2.txt outdir Y
```
`hello world` -> `1<556y.6+5=`
