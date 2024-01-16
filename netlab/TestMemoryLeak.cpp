#include <iostream>
#include "CatchMemoryLeak.h"

using namespace std;

void func() { 
	float* pf = new float;		// memory leak
}

int main() {
	int* ip = new int;
	int* ip1 = new int[10];	
	func();
//	delete[] ip1;
	reportUnreleasedHeap();
	return 0;
}
