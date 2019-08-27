#pragma once
#include <string>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/random.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
namespace bm = boost::multiprecision;

struct Key
{
	bm::int1024_t pkey;
	//公钥(ekey, pkey): (e,n)
	bm::int1024_t ekey;
	//私钥(dkey, pkey): (d, n)
	bm::int1024_t dkey;
};

class RSA
{
public:
	RSA();

	Key getKey()
	{
		return _key;
	}

	void ecrept(const char* plain_file_in, const char* ecrept_file_out,
		bm::int1024_t ekey, bm::int1024_t pkey);//加密
	void decrept(const char* ecrept_file_in, const char* plain_file_out,
		bm::int1024_t dkey, bm::int1024_t pkey);//解密

	std::vector<bm::int1024_t> ecrept(std::string& str_in, bm::int1024_t ekey, bm::int1024_t pkey);//字符串加密
	std::string decrept(std::vector<bm::int1024_t>& ecrept_str, bm::int1024_t dkey, bm::int1024_t pkey);//解密为字符串

	void printInfo(std::vector<bm::int1024_t>& ecrept_str);//打印信息
private:
	bm::int1024_t ecrept(bm::int1024_t msg, bm::int1024_t key, bm::int1024_t pkey);//加密单个信息
	bm::int1024_t produce_prime();//产生素数
	bool is_prime(bm::int1024_t prime);//是否为素数
	bool is_prime_bigInt(bm::int1024_t prime);
	void produce_keys();
	bm::int1024_t produce_pkey(bm::int1024_t prime1, bm::int1024_t prime2);//计算pq乘积n
	bm::int1024_t produce_orla(bm::int1024_t prime1, bm::int1024_t prime2);//计算欧拉函数φ(n)
	bm::int1024_t produce_ekey(bm::int1024_t orla);//产生e
	bm::int1024_t produce_gcd(bm::int1024_t ekey, bm::int1024_t orla);//产生最大公约数
	bm::int1024_t produce_dkey(bm::int1024_t ekey, bm::int1024_t orla);//产生d
	bm::int1024_t exgcd(bm::int1024_t ekey, bm::int1024_t orla,
						bm::int1024_t &x, bm::int1024_t &y);
private:
	Key _key;
};

//	1. 随机选择两个不相等的质数p和q(实际应用中，这两个质数越大，就越难破解)。
//	2. 计算p和q的乘积n，n = pq。
//	3. 计算n的欧拉函数φ(n)。
//	4. 随机选择一个整数e，条件是1 < e < φ(n)，且e与φ(n) 互质。
//	5. 计算e对于φ(n)的模反元素d，使得de≡1 mod φ(n)，即：
//											(de)modφ(n) = 1
//	6. 产生公钥(e, n)，私钥(d, n)。
