ifdef rax
_text segment para 'CODE'
    align 16
    public cannot_be_intercepted
cannot_be_intercepted proc
    xchg edx, esp
    mov ebp, ecx
    xor ebp, ebp
    ret
cannot_be_intercepted endp
endif
end
