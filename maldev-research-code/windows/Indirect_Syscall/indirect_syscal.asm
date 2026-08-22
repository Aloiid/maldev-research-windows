; easy6 indirect syscall 

.data 

EXTERN NtCloseSSN:DWORD
EXTERN NtOpenProcessSSN:DWORD         
EXTERN NtCreateThreadExSSN:DWORD       
EXTERN NtWriteVirtualMemorySSN:DWORD   
EXTERN NtAllocateVirtualMemorySSN:DWORD
EXTERN NtQuerySystemInformationSSN:DWORD

EXTERN NtCloseSYSCALL:UINT_PTR
EXTERN NtOpenProcessSYSCALL:UINT_PTR         
EXTERN NtCreateThreadExSYSCALL:UINT_PTR       
EXTERN NtWriteVirtualMemorySYSCALL:UINT_PTR   
EXTERN NtAllocateVirtualMemorySYSCALL:UINT_PTR
EXTERN NtQuerySystemInformationSYSCALL:UINT_PTR 
EXTERN NtWaitForSingleObjectSYSCALL:UINT_PTR 

.code 

;--------ntclose
NtClose PROC

mov r10, rcx
mov eax, NtCloseSSN
jmp qword ptr [NtCloseSYSCALL]
ret

NtClose ENDP

;--------NtOpenProcess
NtOpenProcess PROC

mov r10, rcx
mov eax, NtOpenProcessSSN
jmp qword ptr [NtOpenProcessSYSCALL]
ret

NtOpenProcess ENDP

;--------NtCreateThreadEx
NtCreateThreadEx PROC

mov r10, rcx
mov eax, NtCreateThreadExSSN
jmp qword ptr [NtCreateThreadExSYSCALL]
ret

NtCreateThreadEx ENDP

;--------NtWriteVirtualMemory
NtWriteVirtualMemory PROC

mov r10, rcx
mov eax, NtWriteVirtualMemorySSN
jmp qword ptr [NtWriteVirtualMemorySYSCALL]
ret

NtWriteVirtualMemory ENDP


;--------NtAllocateVirtualMemory
NtAllocateVirtualMemory PROC

mov r10, rcx
mov eax, NtAllocateVirtualMemorySSN
jmp qword ptr [NtAllocateVirtualMemorySYSCALL]
ret

NtAllocateVirtualMemory ENDP

;--------NtQuerySystemInformation
NtQuerySystemInformation PROC

mov r10, rcx
mov eax, NtQuerySystemInformationSSN
jmp qword ptr [NtQuerySystemInformationSYSCALL]
ret

NtQuerySystemInformation ENDP


NtWaitForSingleObject PROC
mov r10, rcx
mov eax, NtWaitForSingleObjectSSN
jmp qword ptr [NtWaitForSingleObjectSYSCALL]
ret
NtWaitForSingleObject ENDP


end