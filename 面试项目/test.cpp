#include"RSA.h"
#include<iostream>


void teststring()
{
	RSA rsa;
	Key key = rsa.getKey();
	std::string strin;
	while (1)
	{
		std::cout << "输入要加密的信息：" << std::endl;
		std::cin >> strin;
		std::vector<bm::int1024_t>strecrept = rsa.ecrept(strin, key.ekey, key.pkey);
		std::string strout = rsa.decrept(strecrept, key.dkey, key.pkey);
		std::cout << "加密后的信息：" << std::endl;
		rsa.printInfo(strecrept);
		std::cout << "解密后的信息：" << std::endl;
		std::cout << strout << std::endl;
		std::cout << std::endl;

	}
}

void testFile()
{
	double time1, time2;
	RSA rsa;
	Key key = rsa.getKey();
	std::string filename;
	std::cout << "输入文件名：" << std::endl;
	std::cin >> filename;
	std::cout << "开始加密，请等待..." << std::endl;
	time1 = (unsigned int)time(NULL);
	//rsa.ecrept(filename.c_str(), (filename + ".ecrept.txt").c_str(), key.ekey, key.pkey);
	rsa.ecrept(filename.c_str(), (filename + ".ecrept.txt").c_str(), key.ekey, key.pkey);
	time2 = (unsigned int)time(NULL);
	std::cout << "加密完成，用时：" << time2 - time1 << "s" << std::endl;
	std::cout << "正在解密，请等待..." << std::endl;
	time1 = (unsigned int)time(NULL);
	//rsa.decrept((filename + ".ecrept.txt").c_str(), (filename + ".decrept.txt").c_str(), key.dkey, key.pkey);
	rsa.decrept((filename + ".ecrept.txt").c_str(), (filename + ".decrept.txt").c_str(), key.dkey, key.pkey);
	//IO标准库使用C风格字符串而不是C++ string类型字符串作为文件名，所以需要用c_str获取C风格字符串
	//c风格的字符串是可以隐式转换成string的，但string无法隐式转换成c风格的字符串
	//为了把string转换成ifstream可以接受的类型，必须把string转换为c风格的字符串。
	time2 = (unsigned int)time(NULL);
	std::cout << "解密完成，用时：" << time2 - time1 << "s" << std::endl;
}

//void testRandom()
//{
//	//mt19937:一种随机数产生器
//	boost::random::mt19937 gen(time(nullptr));
//	std::cout << "random" << std::endl;
//	//指定随机数的范围 0 ~ (1<<786)
//	boost::random::uniform_int_distribution<bm::cpp_int> dist(0, bm::cpp_int(1) << 768);
//	std::cout << dist(gen) << std::endl;
//}

int main()
{
	srand((unsigned int)time(NULL));
	//teststring();
	testFile();
	system("pause");
	return 0;
}
