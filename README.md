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
./secure_copy <scr_file> <dst_file> <key>
```
### Example
``` bash
./caesar ./libcaesar.so Y data/input.txt data/output.txt
./secure_copy data/input.txt data/output.txt Y
```
`hello world` -> `1<556y.6+5=`
