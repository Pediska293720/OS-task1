## Compilation 

``` bash
make  
```

## Install
``` bash
make install
```

## Usage
``` bash
./caesar <library.so> <key> <scr_file> <dst_file>
./secure_copy <file_1> ... <file_n> <output_dir> <key>
```

### Task 6 usage
```
./secure_copy -add -image disk.img -key 12345678 file.txt

./secure_copy -add -image disk.img -key 12345678 file1.txt file2.txt file3.txt

./secure_copy -list -image disk.img

./secure_copy -get -image disk.img -key 12345678 -out extracted.txt file.txt
```
### Example
``` bash
./caesar ./libcaesar.so Y data/input.txt data/output.txt
./secure_copy data/file1.txt data/file2.txt outdir Y
```
`hello world` -> `1<556y.6+5=`


### tests
./secure_copy --mode=auto test_files/* output_dir/auto_par 3
./secure_copy --mode=auto test_files/file_1.txt test_files/file_2.txt test_files/file_3.txt test_files/file_4.txt  output_dir/auto_seq 3
./secure_copy --mode=auto test_files/* output_dir/auto_par 3