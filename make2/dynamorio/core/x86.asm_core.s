





































































































































































































































































































































   


















































   



   











































































































































































































































































































































































.686 
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 
.CODE




        









































































































































EXTERN get_own_context_integer_control:PROC
EXTERN get_xmm_vals:PROC
EXTERN auto_setup:PROC
EXTERN return_from_native:PROC
EXTERN native_module_callout:PROC
EXTERN dispatch:PROC

EXTERN dr_app_start_helper:PROC

EXTERN dynamo_process_exit:PROC
EXTERN dynamo_thread_exit:PROC
EXTERN dynamo_thread_stack_free_and_exit:PROC
EXTERN dynamorio_app_take_over_helper:PROC
EXTERN found_modified_code:PROC
EXTERN get_cleanup_and_terminate_global_do_syscall_entry:PROC



EXTERN internal_exception_info:PROC
EXTERN is_currently_on_dstack:PROC
EXTERN nt_continue_setup:PROC



EXTERN hashlookup_null_target:PROC











EXTERN dynamorio_earliest_init_takeover_C:PROC
EXTERN os_terminate_wow64_stack:PROC



EXTERN exiting_thread_count:PROC
EXTERN initstack:PROC
EXTERN initstack_mutex:PROC
EXTERN int_syscall_address:PROC
EXTERN syscalls:PROC
EXTERN sysenter_ret_address:PROC
EXTERN sysenter_tls_offset:PROC

EXTERN wow64_index:PROC




        















        dynamo_auto_start PROC

        

        mov      eax, esp
         
 push eax 
 call auto_setup 
 lea esp, [4*1 + esp]
        
        jmp      load_dynamo_failure
        dynamo_auto_start ENDP


































        call_switch_stack PROC

        
















        mov      eax, esp

        
        push     ebx
        push     edi 
        mov      ebx, eax
        mov      edi, esp
        
        mov      edx, [3*4 + eax] 
        mov      ecx, [1*4 + eax] 
        mov      esp, [2*4 + eax] 
        cmp      byte ptr [4*4 + eax], 0 
        je       call_dispatch_alt_stack_no_free









        mov      dword ptr [initstack_mutex], 0 

call_dispatch_alt_stack_no_free:
         
 push ecx 
 call edx 
 lea esp, [4*1 + esp]
        mov      esp, edi
        mov      eax, ebx
        cmp      byte ptr [5*4 + eax], 0 
        je       unexpected_return
        pop      edi
        pop      ebx







        mov      esp, eax

        ret
        call_switch_stack ENDP





        unexpected_return PROC





        

        jmp      unexpected_return
        unexpected_return ENDP







        clone_and_swap_stack PROC

        mov      eax, dword ptr [4 + esp]
        mov      ecx, dword ptr [8 + esp]
        mov      edx, esp
        
        push     esi
        push     edi
        
        sub      ecx, edx 
        mov      esi, edx 
        mov      edi, eax 
        sub      edi, ecx
        sub      eax, ecx 
        
        cld
        rep movsb
        
        pop      edi
        pop      esi
        mov      esp, eax
        ret
        clone_and_swap_stack ENDP





        dr_app_start PROC EXPORT

        sub     esp, 16 - 4  

        
        lea esp, [esp + (- ((8)*(32)) - 24)] 
 push dword ptr [16 - 4 + esp - (- ((8)*(32)) - 24)] 
 pushfd 
 pusha 
 lea eax, [esp] 
  
 push eax 
 call get_xmm_vals 
 lea esp, [4*1 + esp] 
 lea eax, [(10*4 + 24 + ((8)*(32))) + esp] 
 mov [(3*4) + esp], eax 

        
        lea     eax, [esp] 
         
 push eax 
 call dr_app_start_helper 
 lea esp, [4*1 + esp]

        

        add      esp, (10*4 + 24 + ((8)*(32))) + 16 - 4
        ret
        dr_app_start ENDP






        dr_app_take_over PROC EXPORT

        jmp      dynamorio_app_take_over 
        dr_app_take_over ENDP

                




        dynamorio_app_take_over PROC EXPORT

        sub     esp, 16 - 4  

        
        lea esp, [esp + (- ((8)*(32)) - 24)] 
 push dword ptr [16 - 4 + esp - (- ((8)*(32)) - 24)] 
 pushfd 
 pusha 
 lea eax, [esp] 
  
 push eax 
 call get_xmm_vals 
 lea esp, [4*1 + esp] 
 lea eax, [(10*4 + 24 + ((8)*(32))) + esp] 
 mov [(3*4) + esp], eax 

        
        lea      eax, [esp] 
         
 push eax 
 call dynamorio_app_take_over_helper 
 lea esp, [4*1 + esp]

        

        add      esp, (10*4 + 24 + ((8)*(32))) + 16 - 4
        ret
        dynamorio_app_take_over ENDP
        






















        cleanup_and_terminate PROC

        


















        mov      ebp, esp

        










        lock inc dword ptr [exiting_thread_count] 

        
        mov      ebx, dword ptr [4 + esp] 
        mov dword ptr [(((10*4 + 24 + ((8)*(32)))+(4 + 5 * 4)+3*4)+1*4) + ebx], 1
         
 push ebx 
 call is_currently_on_dstack 
 lea esp, [4*1 + esp] 
        cmp      eax, 0
        jnz      cat_save_dstack
        mov      ebx, 0 
        jmp      cat_done_saving_dstack
cat_save_dstack:
        mov ebx, dword ptr [((10*4 + 24 + ((8)*(32)))+(4 + 5 * 4)+3*4) + ebx]
cat_done_saving_dstack:
        


        

         
 call get_cleanup_and_terminate_global_do_syscall_entry 
 lea esp, [4*0 + esp]
        push     ebx 
        push     eax
        
        movzx    esi, byte ptr [5*4 + ebp] 
        cmp      esi, 0
        jz       cat_thread_only
         
 call dynamo_process_exit 
 lea esp, [4*0 + esp]
        jmp      cat_no_thread
cat_thread_only:
         
 call dynamo_thread_exit 
 lea esp, [4*0 + esp]
cat_no_thread:
        


        mov      ecx, 1




cat_spin:       



        xchg     dword ptr [initstack_mutex], ecx 

        jecxz    cat_have_lock
        
        pause    
        jmp      cat_spin
cat_have_lock:
        

        





         
 push -1 
 call os_terminate_wow64_stack 
 lea esp, [4*1 + esp]
        mov      edi, eax    

        mov      esi, [2*4 + ebp]  
        pop      eax             
        pop      ecx             
        mov      ebx, [3*4 + ebp] 
        mov      edx, [4*4 + ebp] 
        





        mov      esp, dword ptr [initstack] 

        

        push     edi   

        push     edx   
        push     ebx   
        push     eax   
        push     esi   
        
         
 push ecx 
 call dynamo_thread_stack_free_and_exit 
 lea esp, [4*1 + esp] 
        
        pop      eax   











        pop      esi   




        pop      edx   
        pop      ecx   



        pop      esp    

        







        mov      dword ptr [initstack_mutex], 0 

        






        lock dec dword ptr [exiting_thread_count] 




        jmp      esi  

        cleanup_and_terminate ENDP









        global_do_syscall_int PROC


        int      02eh










        global_do_syscall_int ENDP



        global_do_syscall_sygate_int PROC

        


        jmp      dword ptr [int_syscall_address]
        global_do_syscall_sygate_int ENDP











        global_do_syscall_sysenter PROC




        sysenter







        global_do_syscall_sysenter ENDP









        global_do_syscall_sygate_sysenter PROC

        mov      esp, edx
        

        pop      dword ptr [esp]
        push     dword ptr [sysenter_ret_address]



        sysenter







        global_do_syscall_sygate_sysenter ENDP

































       global_do_syscall_wow64 PROC

        call     dword ptr fs:[00c0h]



        global_do_syscall_wow64 ENDP




        global_do_syscall_wow64_index0 PROC

        xor      ecx, ecx
        call     dword ptr fs:[00c0h]



        global_do_syscall_wow64_index0 ENDP











        





































        dynamorio_syscall_int2e PROC

        mov      eax, [4 + esp]
        lea      edx, [8 + esp]
        int      02eh
        ret
        dynamorio_syscall_int2e ENDP

        dynamorio_syscall_sygate_int2e PROC

        mov      eax, [4 + esp]
        lea      edx, [8 + esp]
        call     dword ptr [int_syscall_address]
        ret
        dynamorio_syscall_sygate_int2e ENDP
        
        dynamorio_syscall_sysenter PROC

        




        mov      eax, [4 + esp]
        mov      edx, esp



        sysenter

        


        ret
        dynamorio_syscall_sysenter ENDP

        PUBLIC dynamorio_sysenter_fixup
        dynamorio_syscall_sygate_sysenter PROC

        





























        pop      edx
        mov      eax, dword ptr [sysenter_tls_offset]
        mov      fs:[eax], edx
        pop      eax





        push     dynamorio_sysenter_fixup

        push     dword ptr [sysenter_ret_address]
        mov      edx, esp



        sysenter

dynamorio_sysenter_fixup::
        
        push     eax
        
        mov      edx, dword ptr [sysenter_tls_offset]
        push     dword ptr fs:[edx]
        ret
        dynamorio_syscall_sygate_sysenter ENDP




























































        dynamorio_syscall_wow64 PROC

        mov      eax, [4 + esp]
        mov      edx, dword ptr [wow64_index]
        mov      ecx, [edx + eax*4]
        mov      edx, dword ptr [syscalls]
        mov      eax, [edx + eax*4]
        lea      edx, [8 + esp]
        call     dword ptr fs:[00c0h]
        ret
        dynamorio_syscall_wow64 ENDP






        dynamorio_syscall_wow64_noedx PROC

        mov      eax, [4 + esp]
        mov      ecx, dword ptr [syscalls]
        mov      eax, [ecx + eax*4]
        mov      ecx, [esp]
        mov      [esp + 4], ecx
        lea      esp, [esp + 4]
        call     dword ptr fs:[00c0h]
        
        mov      ecx, [esp]
        mov      [esp - 4], ecx
        lea      esp, [esp - 4]
        ret
        dynamorio_syscall_wow64_noedx ENDP
      




















































































































































































































































































































































































































        nt_continue_dynamo_start PROC

        


        
        lea esp, [esp + (- ((8)*(32)) - 24)] 
 push 0 
 pushfd 
 pusha 
 lea eax, [esp] 
  
 push eax 
 call get_xmm_vals 
 lea esp, [4*1 + esp] 
 lea eax, [(10*4 + 24 + ((8)*(32))) + esp] 
 mov [(3*4) + esp], eax
        lea      eax, [esp] 

        



         
 push eax 
 call nt_continue_setup 
 lea esp, [4*1 + esp]
        
        jmp      unexpected_return
        nt_continue_dynamo_start ENDP










        back_from_native_retstubs PROC





        push     0
        jmp      back_from_native
        push     1
        jmp      back_from_native
        push     2
        jmp      back_from_native
        push     3
        jmp      back_from_native
        push     4
        jmp      back_from_native
        push     5
        jmp      back_from_native
        push     6
        jmp      back_from_native
        push     7
        jmp      back_from_native
        push     8
        jmp      back_from_native
        push     9
        jmp      back_from_native
PUBLIC back_from_native_retstubs_end



back_from_native_retstubs_end::
        back_from_native_retstubs ENDP






        back_from_native PROC





        


        
        lea esp, [esp + (- ((8)*(32)) - 24)] 
 push 0 
 pushfd 
 pusha 
 lea eax, [esp] 
  
 push eax 
 call get_xmm_vals 
 lea esp, [4*1 + esp] 
 lea eax, [(10*4 + 24 + ((8)*(32))) + esp] 
 mov [(3*4) + esp], eax
        lea      eax, [esp] 

        






         
 push eax 
 call return_from_native 
 lea esp, [4*1 + esp]
        
        jmp      unexpected_return
        back_from_native ENDP












































        dr_try_start PROC EXPORT

        add      dword ptr [4 + esp], 0
        jmp      dr_setjmp
        dr_try_start ENDP




        dr_setjmp PROC








        mov      edx, dword ptr [4 + esp]

        mov      [       0 + edx], ebx
        mov      [  4 + edx], ecx
        mov      [2*4 + edx], edi
        mov      [3*4 + edx], esi
        mov      [4*4 + edx], ebp
        mov      [5*4 + edx], esp
        mov      eax, [esp]
        mov      [6*4 + edx], eax










        xor      eax, eax
        ret
        dr_setjmp ENDP



        dr_longjmp PROC

        mov      edx, dword ptr [4 + esp]
        mov      eax, dword ptr [8 + esp]

        mov      ebx, [       0 + edx]
        mov      edi, [2*4 + edx]
        mov      esi, [3*4 + edx]
        mov      ebp, [4*4 + edx]
        mov      esp, [5*4 + edx] 
        mov      ecx, [6*4 + edx]
        mov      [esp], ecx    
        mov      ecx, [  4 + edx]










        ret
        dr_longjmp ENDP












        atomic_swap PROC

        mov      eax, dword ptr [8 + esp]
        mov      ecx, dword ptr [4 + esp] 
        xchg     [ecx], eax
        ret
        atomic_swap ENDP




        cpuid_supported PROC

        pushfd
        pop      eax
        mov      ecx, eax      
        xor      eax, 0200000h 
        push     eax
        popfd
        pushfd
        pop      eax
        cmp      ecx, eax
        mov      eax, 0        
        setne    al
        push     ecx         
        popfd
        ret
        cpuid_supported ENDP





        our_cpuid PROC

        mov      edx, dword ptr [4 + esp]
        mov      eax, dword ptr [8 + esp]
        push     ebx 
        push     edi 
        
        mov      edi, edx
        cpuid
        mov      [ 0 + edi], eax
        mov      [ 4 + edi], ebx
        mov      [ 8 + edi], ecx
        mov      [12 + edi], edx
        pop      edi 
        pop      ebx 
        ret
        our_cpuid ENDP




        dr_stmxcsr PROC

        mov      eax, dword ptr [4 + esp]
        stmxcsr  [eax]
        ret
        dr_stmxcsr ENDP




        dr_xgetbv PROC

        mov      eax, dword ptr [4 + esp]
        mov      edx, dword ptr [8 + esp]
        push     eax               
        push     edx               
        mov      ecx, 0
        
        DB 00fh 
 DB 001h 
 DB 0d0h 
    
        pop      ecx
        mov      dword ptr [ecx], eax  
        pop      ecx
        mov      dword ptr [ecx], edx  
        ret
        dr_xgetbv ENDP




        dr_fxsave PROC

        mov      eax, dword ptr [4 + esp]




        fxsave   [eax]

        fnclex
        finit
        ret
        dr_fxsave ENDP




        dr_fnsave PROC

        mov      eax, dword ptr [4 + esp]
        
        fnsave   [eax]
        fwait
        ret
        dr_fnsave ENDP




        dr_fxrstor PROC

        mov      eax, dword ptr [4 + esp]




        fxrstor  [eax]

        ret
        dr_fxrstor ENDP




        dr_frstor PROC

        mov      eax, dword ptr [4 + esp]
        frstor   [eax]
        ret
        dr_frstor ENDP































        get_frame_ptr PROC

        mov      eax, ebp
        ret
        get_frame_ptr ENDP
















        call_modcode_alt_stack PROC

        mov      eax, dword ptr [4 + esp] 
        mov      ebx, dword ptr [8 + esp]
        mov      edi, dword ptr [12 + esp]
        mov      esi, dword ptr [16 + esp]
        mov      edx, dword ptr [20 + esp]
        mov      ecx, dword ptr [28 + esp]
        
        cmp      dword ptr [24 + esp], 0
        je       call_modcode_alt_stack_no_free
        mov      dword ptr [initstack_mutex], 0 
call_modcode_alt_stack_no_free:
        mov esp, dword ptr [((10*4 + 24 + ((8)*(32)))+(4 + 5 * 4)+3*4) + eax]
         
 push ecx 
 push edx 
 push esi 
 push edi 
 push ebx 
 push eax 
 call found_modified_code 
 lea esp, [4*6 + esp]
        
        jmp      unexpected_return
        ret
        call_modcode_alt_stack ENDP































































        get_segments_defg PROC

        xor      eax, eax           
        mov      ecx, dword ptr [4 + esp]
        mov      ax, ds
        mov      [ecx], eax
        mov      ecx, dword ptr [8 + esp]
        mov      ax, es
        mov      [ecx], eax
        mov      ecx, dword ptr [12 + esp]
        mov      ax, fs
        mov      [ecx], eax
        mov      ecx, dword ptr [16 + esp]
        mov      ax, gs
        mov      [ecx], eax
        ret
        get_segments_defg ENDP


        get_segments_cs_ss PROC

        xor      eax, eax           
        mov      ecx, dword ptr [4 + esp]
        mov      ax, cs
        mov      [ecx], eax
        mov      ecx, dword ptr [8 + esp]
        mov      ax, ss
        mov      [ecx], eax
        ret
        get_segments_cs_ss ENDP







        get_own_context_helper PROC

        
        push     ebx
        push     esi
        push     edi





        
        
        
        lea esp, [esp + (- ((8)*(32)) - 24)] 
 push [(3 * 4) + esp - (- ((8)*(32)) - 24)] 
 pushfd 
 pusha 
 lea eax, [esp] 
  
 push eax 
 call get_xmm_vals 
 lea esp, [4*1 + esp] 
 lea eax, [(10*4 + 24 + ((8)*(32))) + esp] 
 mov [(3*4) + esp], eax
        


        lea      esi, [esp] 



        
        mov      eax, [(10*4 + 24 + ((8)*(32))) + (4 * 4) + esp]

        xor      edi, edi
        mov      di, ss
        xor      ebx, ebx
        mov      bx, cs
         
 push esi 
 push edi 
 push ebx 
 push eax 
 call get_own_context_integer_control 
 lea esp, [4*4 + esp]
        add      esp, (10*4 + 24 + ((8)*(32)))
        pop      edi
        pop      esi
        pop      ebx
        ret
        get_own_context_helper ENDP












        get_xmm_caller_saved PROC

        mov      eax, dword ptr [4 + esp]
        movups   [eax + 0*32], xmm0
        movups   [eax + 1*32], xmm1
        movups   [eax + 2*32], xmm2
        movups   [eax + 3*32], xmm3
        movups   [eax + 4*32], xmm4
        movups   [eax + 5*32], xmm5














        ret
        get_xmm_caller_saved ENDP







        get_ymm_caller_saved PROC

        mov      eax, dword ptr [4 + esp]
       









        DB 0c5h 
 DB 0feh 
 DB 07fh 
 DB 000h 

        DB 0c5h 
 DB 0feh 
 DB 07fh 
 DB 048h 
 DB 020h 

        DB 0c5h 
 DB 0feh 
 DB 07fh 
 DB 050h 
 DB 040h 

        DB 0c5h 
 DB 0feh 
 DB 07fh 
 DB 058h 
 DB 060h 

        DB 0c5h 
 DB 0feh 
 DB 07fh 
 DB 0a0h 
 DB 080h 
 DB 000h 
 DB 000h 
 DB 000h 

        DB 0c5h 
 DB 0feh 
 DB 07fh 
 DB 0a8h 
 DB 0a0h 
 DB 000h 
 DB 000h 
 DB 000h 





























        ret
        get_ymm_caller_saved ENDP





        hashlookup_null_handler PROC










        jmp      dword ptr [hashlookup_null_target] 

        hashlookup_null_handler ENDP















































































PUBLIC safe_read_asm_pre
PUBLIC safe_read_asm_mid
PUBLIC safe_read_asm_post
PUBLIC safe_read_asm_recover













        safe_read_asm PROC

        mov eax, dword ptr [4 + esp] 
 mov ecx, dword ptr [8 + esp] 
 mov edx, dword ptr [12 + esp] 
 push edi 
 push esi 
 mov edi, eax 
 mov esi, ecx           
        
        mov ecx, esi 
 and ecx, (4 - 1) 
 jz safe_read_asm_aligned 
 neg ecx 
 add ecx, 4 
 cmp edx, ecx 
 cmovb ecx, edx 
 sub edx, ecx 
safe_read_asm_pre:: 
 rep movsb 
safe_read_asm_aligned: 
 
 mov ecx, edx 
 shr ecx, 2 
safe_read_asm_mid:: 
 rep movsd 
 
 mov ecx, edx 
 and ecx, (4 - 1) 
safe_read_asm_post:: 
 rep movsb
safe_read_asm_recover::
        mov     eax, esi        
        pop esi 
 pop edi
        ret
        safe_read_asm ENDP





































































































































        dr_fpu_exception_init PROC

        fninit
        push     01f80h
        ldmxcsr  dword ptr [esp]
        pop      eax
        ret
        dr_fpu_exception_init ENDP







        get_stack_ptr PROC

        mov      eax, esp
        add      eax, 4 
        ret
        get_stack_ptr ENDP







        load_dynamo PROC

    





























        
        mov      edi, edi























        
        pop      ebx 
        
        pop      eax 
         
 push eax 
 call ebx 

        
        cmp      eax, 0
        jne      load_dynamo_success
        pop      ebx 
        pop      ebx 
        jmp      load_dynamo_failure
load_dynamo_success:
        
        pop      ebx 
        
        
        pop      edi 
         
 push edi 
 push eax 
 call ebx 
        cmp      eax, 0
        je       load_dynamo_failure

        
        jmp      eax
        


        load_dynamo ENDP











        load_dynamo_failure PROC

        



        mov      eax, [((3*4)) + esp] 
        mov      ebx, [(9*4) + esp] 
        
        mov      [-4 + eax], ebx
        


        popa
        popfd
        
        
        
        mov      esp, [-(9*4) + ((3*4)) + esp]
        jmp      dword ptr [-4 + esp]      

        ret
        load_dynamo_failure ENDP
        




















        switch_modes_and_load PROC

        
        mov      eax, dword ptr [4 + esp]
        mov      ecx, dword ptr [8 + esp]
        mov      edx, dword ptr [12 + esp]
        
        push     ebx
        
        DB 0eah 

        DD offset sml_transfer_to_64
        DB 033h
        DB 000h 

sml_transfer_to_64:
    


       





        DB 04ch 
 DB 08bh 
 DB 0cah 
  
        DB 04ch 
 DB 08bh 
 DB 0c1h 
  
        push     0               
        lea      edx, dword ptr [esp] 
        xor      ecx, ecx        
        
        DB 041h 
 push     esp 
        DB 041h 
 push     ebp 
        DB 041h 
 push     esi 
        DB 041h 
 push     edi 
        
        mov      ebx, esp        
        sub      esp, 32         
        and      esp, 0fffffff0h 
        call     eax
        mov      esp, ebx        
        
        DB 041h 
 pop      edi 
        DB 041h 
 pop      esi 
        DB 041h 
 pop      ebp 
        DB 041h 
 pop      esp 
        
        push     offset sml_return_to_32  
        mov      dword ptr [esp + 4], 023h 
        jmp      fword ptr [esp]
sml_return_to_32:
        add      esp, 16         
        pop      ebx             
        ret                      
        switch_modes_and_load ENDP






        switch_modes_and_call PROC

        mov      eax, dword ptr [4 + esp]
        mov      ecx, dword ptr [8 + esp]
        mov      edx, dword ptr [12 + esp]
        
        push     ebx
        mov      ebx, dword ptr [16 + esp]
        
        DB 0eah 

        DD offset smc_transfer_to_64
        DB 033h
        DB 000h 

smc_transfer_to_64:
    


        
        DB 041h 
 push     esp 
        DB 041h 
 push     ebp 
        DB 041h 
 push     esi 
        DB 041h 
 push     edi 
        DB 044h 
 mov      eax, ebx 
        
        mov      ebx, esp        
        sub      esp, 32         
        and      esp, 0fffffff0h 
        call     eax             
        mov      esp, ebx        
        
        DB 041h 
 pop      edi 
        DB 041h 
 pop      esi 
        DB 041h 
 pop      ebp 
        DB 041h 
 pop      esp 
        
        push     offset smc_return_to_32  
        mov      dword ptr [esp + 4], 023h 
        jmp      fword ptr [esp]
smc_return_to_32:
        add      esp, 8          
        pop      ebx             
        ret                      
        switch_modes_and_call ENDP







        dr_invoke_x64_routine PROC EXPORT

        
        mov      eax, esp
        
        push     ebx
        
        DB 0eah 

        DD offset inv64_transfer_to_64
        DB 033h
        DB 000h 

inv64_transfer_to_64:
    


        





        DB 041h 
 push     esp 
        DB 041h 
 push     ebp 
        DB 041h 
 push     esi 
        DB 041h 
 push     edi 
        
        mov      ebx, esp        
        sub      esp, 32         
        mov      ecx, dword ptr [12 + eax] 
        sub      ecx, 4
        jle      inv64_arg_copy_done
        shl      ecx, 3          
        sub      esp, ecx        
        and      esp, 0fffffff0h 
        
        mov      ecx, dword ptr [12 + eax] 
        cmp      ecx, 0
        je       inv64_arg_copy_done
inv64_arg_copy_loop:
        mov      edx, dword ptr [12 + 4*ecx + eax] 
        



        DB 048h 
 DB 063h 
 DB 0d2h 
  
        DB 048h 
  
        mov      dword ptr [-8 + 8*ecx + esp], edx
        sub      ecx, 1 
        jnz      inv64_arg_copy_loop
inv64_arg_copy_done:
        
        mov      ecx, dword ptr [12 + eax] 
        cmp      ecx, 4
        jl       inv64_arg_lt4
        mov      edx, dword ptr [12 + 4*4 + eax] 
        DB 04ch 
 DB 063h 
 DB 0cah 
 
inv64_arg_lt4:
        cmp      ecx, 3
        jl       inv64_arg_lt3
        mov      edx, dword ptr [12 + 4*3 + eax] 
        DB 04ch 
 DB 063h 
 DB 0c2h 
 
inv64_arg_lt3:
        cmp      ecx, 2
        jl       inv64_arg_lt2
        mov      edx, dword ptr [12 + 4*2 + eax] 
        DB 048h 
 DB 063h 
 DB 0d2h 
  
inv64_arg_lt2:
        cmp      ecx, 1
        jl       inv64_arg_lt1
        mov      ecx, dword ptr [12 + 4*1 + eax] 
        DB 048h 
 DB 063h 
 DB 0c9h 
  
inv64_arg_lt1:
        
        DB 048h 
  
        mov      eax, dword ptr [4 + eax] 
        DB 048h 
 call     eax
        
        DB 048h 
 mov      edx, eax
        DB 048h 
 shr      edx, 32
        mov      esp, ebx        
        
        DB 041h 
 pop      edi 
        DB 041h 
 pop      esi 
        DB 041h 
 pop      ebp 
        DB 041h 
 pop      esp 
        
        push     offset inv64_return_to_32  
        mov      dword ptr [esp + 4], 023h 
        jmp      fword ptr [esp]
inv64_return_to_32:
        add      esp, 8          
        pop      ebx             
        ret                      
        dr_invoke_x64_routine ENDP
















        dynamorio_earliest_init_takeover PROC EXPORT

        pusha














        
         
 push eax 
 call dynamorio_earliest_init_takeover_C 
 lea esp, [4*1 + esp]
        

        
        popa
        ret
        dynamorio_earliest_init_takeover ENDP




END

