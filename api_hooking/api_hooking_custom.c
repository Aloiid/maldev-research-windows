
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#pragma comment(lib, "User32.lib")
typedef unsigned long long uint64_t;
typedef unsigned int       uint32_t;
typedef unsigned char      uint8_t;

#ifdef _M_X64
    #define TRAMPOLINE_SIZE 13
#endif

#ifdef _M_X86
    #define TRAMPOLINE_SIZE 7
#endif

typedef struct st_hook{
PVOID pfunctionToHook;  
PVOID pMaliciousfunctionToRun; 
BYTE OriginalBytes[TRAMPOLINE_SIZE];
DWORD OldProtection; 
}hook, *phook; 

//notre fonction malicieuse (remplacer par un shellcode)
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    printf("[+] Original Parameters : \n");
    printf("\t - lpText : %s\n", lpText);
    printf("\t - lpCaption  : %s\n", lpCaption);
    return MessageBoxW(hWnd, L"je suis mechant", L"Hooked MsgBox", uType);
}

int main(int argc, char* argv[]){

    hook Hook = {0};

    Hook.pMaliciousfunctionToRun = (PVOID)&MyMessageBoxA;
    Hook.pfunctionToHook = (PVOID)&MessageBoxA;


    //on va créer le trampoline jmp 
    #ifdef _M_X64

        uint8_t trampoline [] = {0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
        0x41, 0xFF, 0xE2 };

        //patch récupère l'adresse de notre fonction malicieuse 
        uint64_t patch = (uint64_t)Hook.pMaliciousfunctionToRun; 


        //on déxor la fonction avant de la copier dans le trampoline : 

        
        //on met dans la deuxieme adresse de trampoline notre fonction malicieuse grace à patch
        memcpy(&trampoline[2], &patch, sizeof(patch)); 

    #endif

    #ifdef _M_X86
        uint8_t trampoline [] = {0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, pFunctionToRun
        0xFF, 0xE0}; // jmp eax 
        uint32_t patch = (uint32_t)Hook.pMaliciousfunctionToRun; 
        memcpy(&trampoline[1], &patch, sizeof(patch)); //on met l'adresse de notre shellcode dans le trampoline
    #endif

//on sauvegarde la focntion victime dans la variable original bytes
memcpy(Hook.OriginalBytes, Hook.pfunctionToHook, TRAMPOLINE_SIZE);   // save


//on va changer la protection de la zone mémoire de la fonction a hooker : 
//la fonction victime est de base dans la zone mémoire avec une certaine protection
//on va la changer pour nous permettre d'écraser cette focntion avec notre mauvaise fonction
if(!VirtualProtect(Hook.pfunctionToHook, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &Hook.OldProtection)){
    return 1;
    }

//comme on a changé la protection de la zone mémoire ous e trouvait la fonction victime on peut l'écraser avec notre trampoline
//maintenant on va mettre le trampoline a l'adresse de la vrai fonction a dévier
memcpy(Hook.pfunctionToHook, trampoline, TRAMPOLINE_SIZE);           // hook


//comme notre fonction victime à maintenant un jmp vers notre fonction malicieuse
//si on call notre fonction vitime, le rip va suivre le jmp vers notre fonction malicieuse
MessageBoxA(NULL, "What Do You Think About Malware Development ?", "Original MsgBox", MB_OK | MB_ICONQUESTION);
//normalement on devrais tomber sur notre fonction malicieuse

//ensuite on va unhooker notre fonction
printf("on va unhooker la fonction :"); 
getchar(); 


memcpy(Hook.pfunctionToHook, Hook.OriginalBytes, TRAMPOLINE_SIZE);   // unhook

//on va clean le buffer 
memset(Hook.OriginalBytes, 0, TRAMPOLINE_SIZE);

//on remet la protection de base de la focntion victime 
if(!VirtualProtect(Hook.pfunctionToHook, TRAMPOLINE_SIZE, Hook.OldProtection, &Hook.OldProtection)){
    return 1;
    }

//et on recall notre focntion victime et normalement elle s'exécuteras normalement (notre fonction vicitme ici est messagebox)

MessageBoxA(NULL, "Normal MsgBox Again", "Original MsgBox", MB_OK | MB_ICONINFORMATION);


    return 0; 
}
