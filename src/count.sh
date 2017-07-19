echo "base+gil+garl:"
find edu/sharif/twinner/se/ -type f -name \*.cpp -o -name \*.h | xargs cat | grep -v -e '^$' | grep -v -e '//.*' | wc
echo "base+gil:"
find edu/sharif/twinner/se.gil/ -type f -name \*.cpp -o -name \*.h | xargs cat | grep -v -e '^$' | grep -v -e '//.*' | wc
echo "base:"
find edu/sharif/twinner/se.base/ -type f -name \*.cpp -o -name \*.h | xargs cat | grep -v -e '^$' | grep -v -e '//.*' | wc
