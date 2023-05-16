#!/bin/sh
pushd ..
git clone https://github.com/apache/incubator-kvrocks.git kvrocks
pushd kvrocks
git checkout 2.4
./x.py build
popd
popd
