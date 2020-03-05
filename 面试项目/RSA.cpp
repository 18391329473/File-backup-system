#include"RSA.h"
#include<time.h>
#include<math.h>
#include<iostream>
#include<fstream>

RSA::RSA()
{
	produce_keys();
}

void RSA::ecrept(const char* plain_file_in, const char* ecrept_file_out,
	bm::int1024_t ekey, bm::int1024_t pkey)//加密
{
	std::ifstream fin(plain_file_in, std::ifstream::binary);
	std::ofstream fout(ecrept_file_out, std::ofstream::binary);
	if (!fin.is_open())
	{
		std::cout << "open file failed" << std::endl;
		return;
	}
	const int NUM = 128;
	char buffer[NUM];
	bm::int1024_t buffer_out[NUM];
	int curNum;
	while (!fin.eof())
	{
		fin.read(buffer, NUM);
		curNum = fin.gcount();
		for (int i = 0; i < curNum; ++i)
		{
			buffer_out[i] = ecrept(buffer[i], ekey, pkey);
		}
		fout.write((char *)buffer_out, curNum * sizeof(bm::int1024_t));
	}
	fin.close();
	fout.close();
}
void RSA::decrept(const char* ecrept_file_in,const char* plain_file_out,
	bm::int1024_t dkey, bm::int1024_t pkey)//解密
{
	std::ifstream fin(ecrept_file_in, std::ifstream::binary);
	std::ofstream fout(plain_file_out, std::ofstream::binary);
	if (!fin.is_open())
	{
		std::cout << "open file failed" << std::endl;
		return;
	}
	const int NUM = 128;
	bm::int1024_t buffer[NUM];
	char buffer_out[NUM];
	int curNum;
	while (!fin.eof())
	{
		fin.read((char *)buffer, NUM * sizeof(bm::int1024_t));
		curNum = fin.gcount() / sizeof(bm::int1024_t);
		for (int i = 0; i < curNum; ++i)
		{
			buffer_out[i] = (char)ecrept(buffer[i], dkey, pkey);
		}
		fout.write(buffer_out, curNum);
	}
	fin.close();
	fout.close();
}

std::vector<bm::int1024_t> RSA::ecrept(std::string& str_in, bm::int1024_t ekey, bm::int1024_t pkey)//字符串加密
{
	std::vector<bm::int1024_t> vecout;
	size_t sz = str_in.size();
	for (const auto& e : str_in)
	{
		vecout.push_back(ecrept(e, ekey, pkey));
	}
	return vecout;
}
std::string RSA::decrept(std::vector<bm::int1024_t>& ecrept_str, bm::int1024_t dkey, bm::int1024_t pkey)//解密为字符串
{
	std::string strout;
	for (const auto& e : ecrept_str)
	{
		strout.push_back((char)ecrept(e, dkey, pkey));
	}
	return strout;
}

void RSA::printInfo(std::vector<bm::int1024_t>& ecrept_str)//打印信息
{
	for (const auto & e : ecrept_str)
	{
		std::cout << e << ' ';
	}
	std::cout << std::endl;
}


//模幂运算(a^b)%c   
bm::int1024_t RSA::ecrept(bm::int1024_t msg, bm::int1024_t key, bm::int1024_t pkey)
{
	bm::int1024_t msg_out = 1;
	//A0:a^(2^0) = a^1 = a
	bm::int1024_t a = msg;
	bm::int1024_t b = key;
	bm::int1024_t c = pkey;
	while (b)
	{
		if (b & 1)
			//msg_out = (A0 * A1 ...Ai ... An) % c
			msg_out = (msg_out * a) % c;
		b >>= 1;
		//Ai = (A(i - 1) * A(i - 1)) % c
		a = (a * a) % c;
	}
	return msg_out;
}

//随机产生一个素数
bm::int1024_t RSA::produce_prime()
{
	//srand(time(nullptr));
	bm::int1024_t prime = 0;

	//mt19937:一种随机数产生器
	boost::random::mt19937 gen(time(nullptr));

	//指定随机数的范围 2 ~ (1<<128)
	boost::random::uniform_int_distribution<bm::int1024_t> dist(2, bm::int1024_t(1) << 16);

	while (1)
	{
		prime = dist(gen);
		if (is_prime_bigInt(prime))
			break;
	}
	return prime;
}

bool RSA::is_prime(bm::int1024_t prime)
{
	if (prime < 2)
		return false;
	for (bm::int1024_t i = 2; i < sqrt(prime); ++i)
	{
		if (prime % i == 0)
			return false;
	}
	return true;
}

bool RSA::is_prime_bigInt(const bm::int1024_t digit)
{
	boost::random::mt11213b gen(time(nullptr));
	if (miller_rabin_test(digit, 25, gen)) //素数测试算法miller_rabin_test（）
	{
		if (miller_rabin_test((digit - 1) / 2, 25, gen))
		{
			return true;
		}
	}
	return false;

}

void RSA::produce_keys()
{
	bm::int1024_t prime1 = produce_prime();
	bm::int1024_t prime2 = produce_prime();
	while (prime1 == prime2)
		prime2 = produce_prime();
	_key.pkey = produce_pkey(prime1, prime2);
	bm::int1024_t orla = produce_orla(prime1, prime2);
	_key.ekey = produce_ekey(orla);
	_key.dkey = produce_dkey(_key.ekey, orla);
}

bm::int1024_t RSA::produce_pkey(bm::int1024_t prime1, bm::int1024_t prime2)
{
	return prime1 * prime2;
}

bm::int1024_t RSA::produce_orla(bm::int1024_t prime1, bm::int1024_t prime2)
{
	return (prime1 - 1) * (prime2 - 1);
}

//随机选择一个整数e，条件是1 < e < φ(n)，且e与φ(n) 互质
bm::int1024_t RSA::produce_ekey(bm::int1024_t orla)
{
	bm::int1024_t ekey;
	srand(time(nullptr));
	while (1)
	{
		ekey = rand() % orla;
		if (ekey > 1 && produce_gcd(ekey, orla) == 1)
			break;
	}
	return ekey;
}

//求最大公约数
bm::int1024_t RSA::produce_gcd(bm::int1024_t ekey, bm::int1024_t orla)
{
	//gcd(a, b)------gcd(b ,a%b)
	bm::int1024_t ret;
	while (ret = ekey % orla)
	{
		ekey = orla;
		orla = ret;
	}
	return orla;
}

bm::int1024_t RSA::produce_dkey(bm::int1024_t ekey, bm::int1024_t orla)
{
	bm::int1024_t x, y;
	exgcd(ekey, orla, x, y);
	return (x % orla + orla) % orla;
}



/*
扩展的欧几里得算法
x = y1; y = x1 - [a/b]*y1
*/

bm::int1024_t RSA::exgcd(bm::int1024_t ekey, bm::int1024_t orla,
	bm::int1024_t &x, bm::int1024_t &y)
{
	if (orla == 0)
	{
		x = 1;
		y = 0;
		return ekey;
	}
	bm::int1024_t ret = exgcd(orla, ekey % orla, x, y);
	bm::int1024_t x1 = x, y1 = y;
	x = y1;
	y = x1 - (ekey / orla) * y1;
	return ret;
}
