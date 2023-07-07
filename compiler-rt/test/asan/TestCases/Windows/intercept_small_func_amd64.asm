_text segment para 'CODE'
    align 16
    public test1_default
test1_default proc
    cmp rcx, rdx
    ret
test1_default endp
end
