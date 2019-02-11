#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <glob.h>
#include <string.h>
#include <map>
#include <signal.h>
#include <errno.h>

using namespace std;

map<string,string> getAccessMap(char * path);
map<string,struct file_permission> get_perm_map();
void senderrtochild(user_regs_struct regs, long child);

struct file_permission {
    int read;
    int write;
    int exec;
};

int main(int argc, char **argv) {   
	pid_t child;
	long orig_rax,rax;
    struct user_regs_struct regs;
    int status;
    int insyscall = 0;
    char *foi = NULL;
    map<int,string> fd_to_fpath;
    int flag=0;

    int option_index = 0;
    char * filepath = NULL;
    while (( option_index = getopt(argc, argv, "c:")) != -1) {
        switch(option_index) {
            case 'c':
                filepath = optarg;
                flag =1;
                break;
            default:
                break;
                
        }
    }

    if(filepath==NULL) {
        flag=0;
        char * trial1 = "./fendrc";
        char * trial2 = "/fendrc";
        int result = access(trial1, F_OK);
        if(result == 0) filepath = trial1;
        else {
            filepath = (char *) malloc(strlen(getenv("HOME") + strlen(trial2) + 1));
            strcpy(filepath, getenv("HOME"));
            strcat(filepath, trial2);
            result = access(filepath, F_OK);
            if(result!=0) {
                printf("Must provide a config file\n");
                return 1;
            }
        }
    }

    char **args;
    if(flag == 0) {
        args = (char **) malloc(argc-1);
        memcpy(args, argv+1, (argc-1) * sizeof(char*));
        args[argc-1] = NULL;
    } else {     
        args = (char **) malloc(argc-3);  
        memcpy(args, argv+3, (argc-3) * sizeof(char*));
        args[argc-3] = NULL;
    }  
    

    map<string,string> access_map = getAccessMap(filepath);
    map<string,struct file_permission> perm_map = get_perm_map();

    // map<string,string>::iterator itr23; 
    // printf("Access map: \n");
    // for (itr23 = access_map.begin(); itr23 != access_map.end(); ++itr23) { 
    //    printf("%s -> %s\n", itr23->first.c_str(),itr23->second.c_str());

    // }

    child = fork();
    if(child == 0) {
       	ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        //printf("%s %s %s\n",args[0], args[1], args[2]);
        execvp(args[0], args);
       	
    }
    else {
        while(1) {
            wait(&status);
            if(WIFEXITED(status))
                break;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            orig_rax = ptrace(PTRACE_PEEKUSER, child, 8*ORIG_RAX, NULL);
            if(orig_rax == SYS_openat || orig_rax == SYS_open) {
                int len = 4096;
                char buffer[len];
                int i = 0;
                int long_size = sizeof(long);
                int j = len / long_size;
                char *laddr = buffer;
                long mode;
                char *child_addr;
                if(insyscall == 0) {
                    insyscall = 1;
                    //printf("Function %ld called with (%lld, %lld, %lld)\n",orig_rax, regs.rdi, regs.rsi, regs.rdx);
                    mode = regs.rdx;
                    if(orig_rax == SYS_openat) child_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RSI, 0);
                    else child_addr = (char *) ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RDI, 0);
                    while(i < j) {
                        long data = ptrace(PTRACE_PEEKTEXT, child, child_addr + i * 8, NULL);
                        memcpy(laddr, (char *) &data, long_size);
                        ++i;
                        laddr += long_size;
                    }
                    buffer[len] = '\0';
                    //printf("Open file path: %s %ld\n",buffer,mode);
                    foi = buffer;
                    map<string,string>::iterator itr = access_map.find(buffer);
                    if(itr!=access_map.end()) printf("File found\n");
                } else {
                    insyscall = 0;
                    rax = ptrace(PTRACE_PEEKUSER,child,8*RAX);
                    if(rax == -1) {
                        printf("Error occurred %ld\n",rax);
                    }
                    //printf("Open returned with %ld\n",rax);
                    if(fd_to_fpath.find(rax) != fd_to_fpath.end()) fd_to_fpath.erase(rax);
                    char full_path[4096];
                    realpath(buffer,full_path);
                    fd_to_fpath.insert({rax,std::string(full_path)});
                }
            } else if(orig_rax == SYS_read) {
                if(insyscall == 0) {
                    insyscall = 1;
                    long val = ptrace(PTRACE_PEEKUSER, child, 8*RDI, 0);
                    if(fd_to_fpath.find(val) != fd_to_fpath.end()) {
                        map<string,string>::iterator itr222 = access_map.find(fd_to_fpath.find(val)->second);
                        //printf("%s\n",fd_to_fpath.find(val)->second.c_str());
                        if(itr222 != access_map.end()) {
                            if(perm_map.find(itr222->second)->second.read != 1) {
                                senderrtochild(regs,child);
                            }
                        }
                    }
                } else {
                    insyscall = 0;
                    rax = ptrace(PTRACE_PEEKUSER,child,8*RAX);
                    if(rax == -1) {
                        printf("Error occurred %ld\n",rax);
                    }
                    //printf("Read returned with %ld\n",rax);
                }
            } else if(orig_rax == SYS_write) {
                if(insyscall == 0) {
                    insyscall = 1;
                    long val = ptrace(PTRACE_PEEKUSER, child, 8*RDI, 0);
                    if(fd_to_fpath.find(val) != fd_to_fpath.end()) {
                        map<string,string>::iterator itr222 = access_map.find(fd_to_fpath.find(val)->second);
                        if(itr222 != access_map.end()) {
                            if(perm_map.find(itr222->second)->second.write != 1) {
                                senderrtochild(regs,child);
                            }
                        }
                    }
                } else {
                    insyscall = 0;
                    rax = ptrace(PTRACE_PEEKUSER,child,8*RAX);
                    if(rax == -1) {
                        printf("Error occurred %ld\n",rax);
                    }
                    //printf("Write returned with %ld\n",rax);
                }
            } else if(orig_rax == SYS_execve) {
                if(args[1]==NULL) {
                    char fullpath[4096];
                    realpath(args[0],fullpath);
                    map<string,string>::iterator itrx = access_map.find(std::string(fullpath));
                    if(itrx != access_map.end()) {
                        if(perm_map.find(itrx->second)->second.exec != 1) {
                            printf("bash: %s: Permission denied\n", args[0]);
                            kill(child, SIGKILL);
                            return 1;
                        }
                    }
                }
            } else if(orig_rax == SYS_getdents) {
                if(insyscall==0) {
                    insyscall=1;
                    printf("Inside getdents\n");
                    long fd = regs.rdi;
                    if(fd_to_fpath.find(fd) != fd_to_fpath.end()) {
                        map<string,string>::iterator itrgd = access_map.find(fd_to_fpath.find(fd)->second);
                        if(itrgd != access_map.end()) {
                            if(perm_map.find(itrgd->second)->second.read != 1 || perm_map.find(itrgd->second)->second.exec != 1 ) {
                                senderrtochild(regs,child);
                            }
                        }
                    }
                } else {
                    insyscall = 0;
                    rax = ptrace(PTRACE_PEEKUSER,child,8*RAX);
                    if(rax == -1) {
                        printf("Error occurred %ld\n",rax);
                    }
                    //printf("getdents returned with %ld\n",rax);
                }
            }
            ptrace(PTRACE_SYSCALL,child,NULL,NULL);
        }
    }

    // map<int,string>::iterator itr22; 
    // printf("map is \n");
    // for (itr22 = fd_to_fpath.begin(); itr22 != fd_to_fpath.end(); ++itr22) { 
    //    printf("%d -> %s\n", itr22->first,itr22->second.c_str());

    // }
    return 0;
}

map<string,string> getAccessMap(char * filepath) {
    map<string,string> access_map;
    FILE *fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen(filepath, "r");
    while ((read = getline(&line, &len, fp)) != -1) {
        if(read != 1) {
            char abs_path[4096];
            int i=0;
            char *token;
            char *str = strdup(line);
            int index=0;
            glob_t globlist;

            char * access = strtok(line," \t");
            char * path = strtok(NULL," ");
            access[strcspn(access,"\n")] = 0;
            path[strcspn(path,"\n")] = 0;
            realpath(path,abs_path);
            //printf("%s\n",path );
            glob(abs_path, GLOB_PERIOD, NULL, &globlist);
            while (globlist.gl_pathv[i]) {
                //printf("%s\n", globlist.gl_pathv[i]);
                if(access_map.find(std::string(globlist.gl_pathv[i])) != access_map.end()) access_map.erase(std::string(globlist.gl_pathv[i]));
                access_map.insert({std::string(globlist.gl_pathv[i]), std::string(access)});
                i++;
            }
            globfree(&globlist);
        }
    }
    return access_map;
}

map<string,struct file_permission> get_perm_map() {
    map<string, struct file_permission> perm_map;

    struct file_permission _000;
    _000.read = 0;
    _000.write = 0;
    _000.exec = 0;
    struct file_permission _001;
    _001.read = 0;
    _001.write = 0;
    _001.exec = 1;
    struct file_permission _010;
    _010.read = 0;
    _010.write = 1;
    _010.exec = 0;
    struct file_permission _011;
    _011.read = 0;
    _011.write = 1;
    _011.exec = 1;
    struct file_permission _100;
    _100.read = 1;
    _100.write = 0;
    _100.exec = 0;
    struct file_permission _101;
    _101.read = 1;
    _101.write = 0;
    _101.exec = 1;
    struct file_permission _110;
    _110.read = 1;
    _110.write = 1;
    _110.exec = 0;
    struct file_permission _111;
    _111.read = 1;
    _111.write = 1;
    _111.exec = 1;

    perm_map.insert({"000",_000});
    perm_map.insert({"001",_001});
    perm_map.insert({"010",_010});
    perm_map.insert({"011",_011});
    perm_map.insert({"100",_100});
    perm_map.insert({"101",_101});
    perm_map.insert({"110",_110});
    perm_map.insert({"111",_111});

    return perm_map;
}

void senderrtochild(user_regs_struct regs, long child)
{
    regs.orig_rax = -1;
    ptrace(PTRACE_SETREGS, child, 0, &regs);
    ptrace(PTRACE_SYSCALL, child, NULL, NULL);
    waitpid(child, 0, 0);
    regs.rax = -EACCES;
    ptrace(PTRACE_SETREGS, child, NULL, &regs);
}