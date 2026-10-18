# The client-server runtime's client: the call kernel32's console work goes through.
.text

# CsrClientCallServer(message, capture buffer, API number, data length): send the message (a
# CSR_API_MSG: Windows 2000's header, then the API's data) to the server the API number names and
# wait for its reply; the message's ReturnValue, which is the answer too. Windows 2000 sends it to
# csrss over the process's LPC port; F2K has no csrss, and its stand-in is the kernel's console
# server, reached through one internal service (see rtl::console). The four arguments are the
# service's argument block, where the caller pushed them.
.p2align 4
.globl _f2k_export_CsrClientCallServer
_f2k_export_CsrClientCallServer:
    mov eax, SYS_CSR_CALL
    lea edx, [esp+4]
    int SYSCALL_VECTOR
    ret 16
