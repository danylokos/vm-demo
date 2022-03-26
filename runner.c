// https://googleprojectzero.blogspot.com/2021/05/fuzzing-ios-code-on-macos-at-native.html
//

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>
#include <mach/mach_init.h>
#include <mach/vm_map.h>
#include <mach/vm_page_size.h>
#include <mach-o/loader.h>

extern char **environ;

unsigned int find_func_offset(const char *bin_name, const char *func_name) {    
    size_t needed = snprintf(NULL, 0, "nm %s | grep %s", bin_name, func_name) + 1;
    char *cmd = malloc(needed);
    sprintf(cmd, "nm %s | grep %s", bin_name, func_name);
    FILE* output = popen(cmd, "r");
    
    unsigned int patch_offset;
    int r = fscanf(output, "%x T", &patch_offset);
    if (r != 1) {
        printf("Failed to find offset of %s in %s\n", func_name, bin_name);
        exit(-1);
    }
    printf("[*] %s at offset 0x%x in %s\n", func_name, patch_offset, bin_name);
    return patch_offset;  
}

void patch_add_func(task_t task, vm_address_t image_addr) {
    printf("[*] Patching _add func...\n");
    char bin_name[] = "demo";
    char func_name[] = "_add";
    unsigned int patch_offset = find_func_offset(bin_name, func_name) + 13; // add eax, dword [rbp+var_8] offset
    vm_address_t patch_addr = image_addr + patch_offset;
    // VM_PROT_COPY forces COW, probably, see vm_map_protect in vm_map.c
    kern_return_t kr;
    kr = vm_protect(task, trunc_page(patch_addr), vm_page_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        printf("vm_protect failed\n");
        return;
    }

    // imul eax, dword ptr [ebp - 8]
    // pop ebp
    // ret    
    const char* code = "\x0F\xAF\x45\xF8\x5D\xC3";
    kr = vm_write(task, patch_addr, (vm_offset_t)code, 6);
    if (kr != KERN_SUCCESS) {
        printf("vm_write failed\n");
        return;
    }
    kr = vm_protect(task, trunc_page(patch_addr), vm_page_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        printf("vm_protect failed\n");
        return;
    }    
}

void patch_plus_sign(task_t task, vm_address_t image_addr) {
    printf("[*] Patching '+' sign...\n");
    unsigned int patch_offset = 0x3f9f; // "+" sign offset
    vm_address_t patch_addr = image_addr + patch_offset;
    // VM_PROT_COPY forces COW, probably, see vm_map_protect in vm_map.c
    kern_return_t kr;
    kr = vm_protect(task, trunc_page(patch_addr), vm_page_size, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        printf("vm_protect failed\n");
        return;
    }

    const char* code = "\x2A"; // *
    kr = vm_write(task, patch_addr, (vm_offset_t)code, 1);
    if (kr != KERN_SUCCESS) {
        printf("vm_write failed\n");
        return;
    }
    kr = vm_protect(task, trunc_page(patch_addr), vm_page_size, false, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        printf("vm_protect failed\n");
        return;
    }    
}

vm_address_t find_image_addr(task_t task) {
    kern_return_t kr;
    vm_address_t image_addr = 0;
    int headers_found = 0;
    vm_address_t addr = 0;
    vm_size_t size;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    unsigned int depth = 0;
    while (1) {
        // get next memory region
        kr = vm_region_recurse_64(task, &addr, &size, &depth, (vm_region_info_t)&info, &info_count);
        if (kr != KERN_SUCCESS)
            break;
        unsigned int header;
        vm_size_t bytes_read;
        kr = vm_read_overwrite(task, addr, 4, (vm_address_t)&header, &bytes_read);
        if (kr != KERN_SUCCESS) {
            // TODO handle this, some mappings are probably just not readable
            printf("vm_read_overwrite failed\n");
            exit(-1);
        }
        if (bytes_read != 4) {
            // TODO handle this properly
            printf("[-] vm_read read to few bytes\n");
            exit(-1);
        }
        if (header == MH_MAGIC_64) {
            headers_found++;
        }
        if (headers_found == 1) {
            image_addr = addr;
            break;
        }
        addr += size;
    }
    if (image_addr == 0) {
        printf("[-] Failed to find image\n");
        exit(-1);
    }
    printf("[*] Image mapped at 0x%lx\n", image_addr);
    return image_addr;
}

void instrument(pid_t pid) {
    printf("[*] Patching child process...\n");

    // Attach to the target process
    kern_return_t kr;
    task_t task;
    kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        printf("task_for_pid failed. Is this binary signed and possesses the com.apple.security.cs.debugger entitlement?\n");
        return;
    }

    vm_address_t image_addr = find_image_addr(task);
    patch_add_func(task, image_addr);
    patch_plus_sign(task, image_addr);

    printf("[+] Successfully patched\n");
}

int run(char **argv) {
    pid_t pid;
    int rv;
    posix_spawnattr_t attr;
    rv = posix_spawnattr_init(&attr);
    if (rv != 0) {
        perror("posix_spawnattr_init");
        return -1;
    }
    rv = posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    if (rv != 0) {
        perror("posix_spawnattr_setflags");
        return -1;
    }    
    rv = posix_spawn(&pid, argv[0], NULL, &attr, argv, environ);
    if (rv != 0) {
        perror("posix_spawn");
        return -1;
    }
    printf("[+] Child process created with pid: %i\n", pid);
    instrument(pid);
    printf("[*] Sending SIGCONT to continue child\n");
    kill(pid, SIGCONT);
    int status;
    rv = waitpid(pid, &status, 0);
    if (rv == -1) {
        perror("waitpid");
        return -1;
    }
    printf("[*] Child exited with status %i\n", status);
    posix_spawnattr_destroy(&attr);
    return 0;
}

int attach(char **argv) {
    pid_t pid = atoi(argv[0]);
    if (pid == 0) {
        printf("[-] Failed to convert pid %s", argv[0]);    
    }
    instrument(pid);
    return 0;
}

int main(int argc, char **argv) {
	if (argc < 3) {
        printf("Usage: %s --path path/to/binary\n", argv[0]);
        printf("Usage: %s --pid 123\n", argv[0]);
        return 0;
    }
    if (strcmp(argv[1], "--path") == 0) {
        printf("[*] Preparing to execute binary %s\n", argv[2]);
        return run(argv + 2);
    } else if (strcmp(argv[1], "--pid") == 0) {
        printf("[*] Attaching to pid %s\n", argv[2]);
        return attach(argv + 2);
    }
}
