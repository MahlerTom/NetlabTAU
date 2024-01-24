// CatchMemoryLeak.h Created by Yosi Halakhmi

#ifndef CATCHMEMORYLEAK_H
#define CATCHMEMORYLEAK_H

#include <stdlib.h>

void saveInStorage(	unsigned long addr,  
				unsigned long nBytes,  
				const char *fname, 
				unsigned long lnum);
void removeFromStorage(unsigned long addr);
void reportUnreleasedHeap();

#ifdef _DEBUG

inline void * operator new(	unsigned int size,
					const char *fileNam, int line) 
{	
	void *ptr = (void *)malloc(size);
	saveInStorage((unsigned long)ptr, size, fileNam, line);
	return(ptr);
};

inline void * operator new[](unsigned int size,
					const char * fileNam, int line) 
{	
	void *ptr = (void *)malloc(size);
	saveInStorage((unsigned long)ptr, size, fileNam, line);
	return(ptr);
};

inline void operator delete(void* ptr) {
	removeFromStorage((unsigned long)ptr);
	free(ptr);
};

inline void  operator delete[](void* ptr) {
	removeFromStorage((unsigned long)ptr);
	free(ptr);
};
#endif	// _DEBUG



#ifdef 	DEBUG_NEW
#undef	DEBUG_NEW
#endif

#ifdef 	_DEBUG
#define DEBUG_NEW new(__FILE__, __LINE__)
#else
#define DEBUG_NEW new
#endif
#define new DEBUG_NEW

#endif		// CATCHMEMORYLEAK_H

