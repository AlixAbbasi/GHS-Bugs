# Vulnerabilities in Green Hills INTEGRITY RTOS.
In this report we are reporting vulnerabilities within Integrity RTOS 5.0.4. We will utilize the following vulnerabilities to bypass Interpeak IPShell jail in order to directly talk to the Integrity. 


## Stack Overflow in IPWEBS (CVE-2019-7714)
Interpeka IPWEBS which is being used as a webserver in Green Hills Integrity 5.0.4 has a problem when parsing HTTP headerlines during Authentication. The IPWEBS allocate 60 bytes of buffer to parse HTTP authentication header. However when copying the authentication header to parse it does not check the size of the header leading to a basic buffer overflow. 

In the IPWEBS the variable auth_outbuf with the fixed size of 60 bytes is declared. However the auth_str variable will get copied to the auth_outbuf without being checked, leading to a buffer overflow. 


The assembly code of the function is the following:


```asm
BANK_A:018E2E64 ; =============== S U B R O U T I N E =======================================
BANK_A:018E2E64
BANK_A:018E2E64 ; Attributes: bp-based frame
BANK_A:018E2E64
BANK_A:018E2E64 t_webserver_basic_auth_check            ; CODE XREF: sub_18E4B58+ECp
BANK_A:018E2E64                 MOV             R12, SP
BANK_A:018E2E68                 STMFD           SP!, {R5,R6,R8,R9,R11,R12,LR,PC}
BANK_A:018E2E6C                 SUB             R11, R12, #4
BANK_A:018E2E70                 SUB             SP, SP, #0x20
BANK_A:018E2E74                 MOV             R6, R0
BANK_A:018E2E78                 MOV             R0, SP
BANK_A:018E2E7C                 MOV             R2, #0x20 ; ' '
BANK_A:018E2E80                 MOV             R1, #0
BANK_A:018E2E84                 BL              ipcom_memset
BANK_A:018E2E88                 LDR             R1, =aAuthorization ; "Authorization"
BANK_A:018E2E8C                 MOV             R0, R6  ; content
BANK_A:018E2E90                 BL              t_parse_http_header_content
BANK_A:018E2E94                 MOV             R3, R0
BANK_A:018E2E98                 MOV             R5, R3
BANK_A:018E2E9C                 CMP             R5, #0
BANK_A:018E2EA0                 BEQ             loc_18E2F48
BANK_A:018E2EA4                 MOV             R1, R5
BANK_A:018E2EA8                 LDR             R0, =aBasic ; "Basic"
BANK_A:018E2EAC                 MOV             R2, #5
BANK_A:018E2EB0                 BL              t_strncmp
BANK_A:018E2EB4                 MOV             R3, R0
BANK_A:018E2EB8                 CMP             R3, #0
BANK_A:018E2EBC                 BNE             loc_18E2F58
BANK_A:018E2EC0                 ADD             R5, R5, #5
BANK_A:018E2EC4                 B               loc_18E2ECC
BANK_A:018E2EC8 ; ---------------------------------------------------------------------------
BANK_A:018E2EC8
BANK_A:018E2EC8 loc_18E2EC8                             ; CODE XREF: t_webserver_basic_auth_check+80j
BANK_A:018E2EC8                 ADD             R5, R5, #1
BANK_A:018E2ECC
BANK_A:018E2ECC loc_18E2ECC                             ; CODE XREF: t_webserver_basic_auth_check+60j
BANK_A:018E2ECC                 LDRB            R3, [R5]
BANK_A:018E2ED0                 CMP             R3, #0x20 ; ' '
BANK_A:018E2ED4                 BEQ             loc_18E2EDC
BANK_A:018E2ED8                 B               loc_18E2EE8
BANK_A:018E2EDC ; ---------------------------------------------------------------------------
BANK_A:018E2EDC
BANK_A:018E2EDC loc_18E2EDC                             ; CODE XREF: t_webserver_basic_auth_check+70j
BANK_A:018E2EDC                 LDRB            R3, [R5]
BANK_A:018E2EE0                 CMP             R3, #0
BANK_A:018E2EE4                 BNE             loc_18E2EC8
BANK_A:018E2EE8
BANK_A:018E2EE8 loc_18E2EE8                             ; CODE XREF: t_webserver_basic_auth_check+74j
BANK_A:018E2EE8                 MOV             R1, SP  ; dest
BANK_A:018E2EEC                 MOV             R0, R5  ; src
BANK_A:018E2EF0                 MOV             R2, #0x20 ; ' '
BANK_A:018E2EF4                 BL              t_decode_base64_into
BANK_A:018E2EF8                 MOV             R1, R0
BANK_A:018E2EFC                 CMP             R1, #0
BANK_A:018E2F00                 BNE             loc_18E2F58
BANK_A:018E2F04                 MOV             R0, SP  ; str
BANK_A:018E2F08                 MOV             R1, #0x3A ; ':' ; some_len
BANK_A:018E2F0C                 BL              ipcom_strchr
BANK_A:018E2F10                 MOV             R1, R0
BANK_A:018E2F14                 CMP             R1, #0
BANK_A:018E2F18                 BEQ             loc_18E2F58
BANK_A:018E2F1C                 MOV             R0, SP  ; str
BANK_A:018E2F20                 MOV             R1, #0x3A ; ':' ; some_len
BANK_A:018E2F24                 BL              ipcom_strchr
BANK_A:018E2F28                 MOV             R12, R0
BANK_A:018E2F2C                 MOV             R5, #0x20 ; ' '
BANK_A:018E2F30                 STRB            R5, [R12]
BANK_A:018E2F34                 ADD             R3, R6, #0x198
BANK_A:018E2F38                 ADD             R2, R6, #0x178
BANK_A:018E2F3C                 LDR             R1, =a32s32s ; "%32s %32s"
BANK_A:018E2F40                 MOV             R0, SP
BANK_A:018E2F44                 BL              t_sprintf
BANK_A:018E2F48
BANK_A:018E2F48 loc_18E2F48                             ; CODE XREF: t_webserver_basic_auth_check+3Cj
BANK_A:018E2F48                 ADD             R1, R6, #0x198
BANK_A:018E2F4C                 ADD             R0, R6, #0x178
BANK_A:018E2F50                 BL              check_creds
BANK_A:018E2F54                 B               loc_18E2F5C
BANK_A:018E2F58 ; ---------------------------------------------------------------------------
BANK_A:018E2F58
BANK_A:018E2F58 loc_18E2F58                             ; CODE XREF: t_webserver_basic_auth_check+58j
BANK_A:018E2F58                                         ; t_webserver_basic_auth_check+9Cj ...
BANK_A:018E2F58                 LDR             R0, =0xFFFFFBDC
BANK_A:018E2F5C
BANK_A:018E2F5C loc_18E2F5C                             ; CODE XREF: t_webserver_basic_auth_check+F0j
BANK_A:018E2F5C                 LDMDB           R11, {R5,R6,R8,R9,R11,SP,LR}
BANK_A:018E2F60                 BX              LR
BANK_A:018E2F60 ; End of function t_webserver_basic_auth_check
BANK_A:018E2F60
BANK_A:018E2F64
```


## Interpeak IPCOMShell PWD Command Handler Format String Vulnerability (CVE-2019-7712)

In the function handler for printing the current working directory the directory path is used as a first argu- ment to printf. This leads to a user supplied format string being executed. 


## Interpeak IPCOMShell Print Prompt Heap Overflow Vulnerability (CVE-2019-7713)
There is a heap overflow vulnerability in the IPCOMShell used in Green Hills INTEGRITY RTOS v5.0.4. While it is not documented inside the "helpall" command provided by the IPCOMShell, typing "prompt <new_prompt>" allows the user to set the prompt. Looking at the implementation generating the shell output we can see those different modifiers are interpreted:

* \i print ip address
* \p print shell process name
* \P print shell process ID
* \w and \W print working directory

The function printing the shell prompt allows the use of custom modifiers to display information like process IDs or current IP address or current working directory. The expansion of those modifiers can trigger a heap-based buffer overflow and also leaks process address information potentially valuable to an attacker. This may result in memory corruption, crash or info leak. 




## Interpeak IPCOMShell Undocumented Prompt Command Format String Vulnerability (CVE-2019-7711)

The non-documented shell command "prompt " sets the (user controlled) shell’s prompt value which is used as a format string input to printf, resulting in an information leak. 



## Interpeak IPCOMShell Process Greetings Format String Vulnerability (CVE-2019-7715)
The main shell handler function uses the value of the environment variable "ipcom.shell.greeting" as the first argument to printf. Setting the variable using the sysvar command results in a user-controlled format string during login, resulting in an information leak.


## Credit
Tobias Scharnowski and Ali Abbasi of Ruhr University Bochum
