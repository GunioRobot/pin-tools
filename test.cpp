#include <cstdlib>
#include <unistd.h>
#include <iostream>
#include <sys/mman.h>
#include <cstring>

using namespace std;

int main(int argc, char **argv)
{
	void *buffer;

	cout << "Allocating " << sysconf(_SC_PAGESIZE) << " bytes" << endl;
	if (posix_memalign(&buffer, sysconf(_SC_PAGESIZE), sysconf(_SC_PAGESIZE)))
		return -1;

	mprotect(buffer, sysconf(_SC_PAGESIZE), PROT_READ | PROT_WRITE | PROT_EXEC);

	memset(buffer, 0x90, sysconf(_SC_PAGESIZE));

	((char *) buffer)[sysconf(_SC_PAGESIZE) - 1] = 0xcc;

	((void(*)(void)) buffer)();

	cout << buffer << endl;
}

