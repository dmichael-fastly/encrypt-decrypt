#!/bin/bash

# Use this command to generate the IV: xxd -u -l 16 -p "somestring"
# Use this command to generate the KEY: xxd -u -l 32 -p "someotherstring"
# Note 1: for -K and -iv you must pass a string comprised only of hex digits. You can get this string from a binary file like this:
# hexdump -e '16/1 "%02x"' FILE_WITH_KEY

rm -rf ./encrypted/*.m3u8
rm -rf ./encrypted/stream_0/*
rm -rf ./encrypted/stream_1/*.m3u8
rm -rf ./encrypted/stream_2/*.m3u8
iv = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
key = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
for file in ./stream_0/*;do 
  newFile="${file/stream_0/encrypted\/stream_0}"
  openssl enc -aes-256-cbc -nosalt -e -in $file -out $newFile -K 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' -iv 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
  echo "encrypted $file to $newFile"
done
for file in ./stream_1/*;do 
  newFile="${file/stream_1/encrypted\/stream_1}"
  openssl enc -aes-256-cbc -nosalt -e -in $file -out $newFile -K 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' -iv 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
  echo "encrypted $file to $newFile"
done
for file in ./stream_2/*;do 
  newFile="${file/stream_2/encrypted\/stream_2}"
  openssl enc -aes-256-cbc -nosalt -e -in $file -out $newFile -K 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' -iv 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
  echo "encrypted $file to $newFile"
done
openssl enc -aes-256-cbc -nosalt -e -in ./master.m3u8 -out ./encrypted/master.m3u8 -K 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX' -iv 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
echo "encrypted ./master.m3u8 to ./encrypted/master.m3u8"
