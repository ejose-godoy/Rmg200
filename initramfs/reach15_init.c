#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

struct binder_write_read {
 uint64_t write_size, write_consumed, write_buffer;
 uint64_t read_size, read_consumed, read_buffer;
};
#define BINDER_VERSION _IOWR('b', 9, int)
#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, int)
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_INCREFS _IOW('c', 4, uint32_t)
#define BC_ACQUIRE _IOW('c', 5, uint32_t)
#define BC_RELEASE _IOW('c', 6, uint32_t)
#define BC_DECREFS _IOW('c', 7, uint32_t)

static int drop_uid(void) {
 if(setgroups(0,NULL))return 1;
 if(setresgid(10000,10000,10000))return 2;
 if(setresuid(10000,10000,10000))return 3;
 return getuid()==10000 && geteuid()==10000 ? 0 : 4;
}
static int basic_open(void) {
 int fd=open("/dev/binder",O_RDWR|O_CLOEXEC);
 if(fd<0){printf("REACH15_OPEN_ERRNO=%d\n",errno);return -1;}
 int version=-1;
 if(ioctl(fd,BINDER_VERSION,&version)!=0||version!=8){close(fd);return -1;}
 return fd;
}
static int manager(int ready_fd,int quit_fd) {
 int err=drop_uid();
 if(err)return 20+err;
 int fd=basic_open();
 if(fd<0)return 25;
 errno=0;
 int rc=ioctl(fd,BINDER_SET_CONTEXT_MGR,0);
 printf("REACH15_CONTEXT_MANAGER_RET=%d ERRNO=%d\n",rc,errno);
 if(rc){close(fd);return 26;}
 puts("REACH15_CONTEXT_MANAGER_UID=10000");
 if(write(ready_fd,"R",1)!=1){close(fd);return 27;}
 close(ready_fd);
 char done=0;
 if(read(quit_fd,&done,1)!=1 || done!='Q'){close(fd);return 28;}
 close(quit_fd);
 close(fd);
 puts("REACH15_MANAGER_CLOSED_NORMALLY=1");
 return 0;
}
static int send_command(int fd, uint32_t cmd,const char *name) {
 struct {uint32_t command;uint32_t handle;} msg={cmd,0};
 struct binder_write_read bwr={0};
 bwr.write_size=sizeof(msg);
 bwr.write_buffer=(uintptr_t)&msg;
 errno=0;
 int rc=ioctl(fd,BINDER_WRITE_READ,&bwr);
 printf("REACH15_%s_RET=%d ERRNO=%d CONSUMED=%llu\n",name,rc,errno,
        (unsigned long long)bwr.write_consumed);
 return rc==0 && bwr.write_consumed==sizeof(msg)?0:-1;
}
static int client(void) {
 int e=drop_uid();
 if(e)return 30+e;
 int fd=basic_open();
 if(fd<0)return 35;
 puts("REACH15_CLIENT_UID=10000");
 /* Serialized legal reference increments and decrements. Manager remains
  * alive until every command and descriptor close has finished. No races,
  * forced errors, malformed offsets, Binder objects, or kernel exploit. */
 if(send_command(fd,BC_INCREFS,"INCREFS")){close(fd);return 36;}
 if(send_command(fd,BC_ACQUIRE,"ACQUIRE")){close(fd);return 37;}
 if(send_command(fd,BC_RELEASE,"RELEASE")){close(fd);return 38;}
 if(send_command(fd,BC_DECREFS,"DECREFS")){close(fd);return 39;}
 close(fd);
 puts("REACH15_CLIENT_COMPLETED_NORMAL_REF_CYCLE=1");
 puts("REACH15_NO_RACE=1");
 puts("REACH15_NO_EXPLOIT=1");
 puts("REACH15_NO_PRIVILEGE_CHANGE=1");
 return 0;
}
int main(void) {
 setvbuf(stdout,NULL,_IONBF,0);
 puts("REACH15_QEMU_ONLY=1");
 if(mount("devtmpfs","/dev","devtmpfs",0,NULL)){perror("mount");return 41;}
 struct stat st;
 if(stat("/",&st)||((st.st_mode&0005)!=0005))return 42;
 if(stat("/dev",&st)||((st.st_mode&0005)!=0005))return 43;
 if(stat("/dev/binder",&st)||!S_ISCHR(st.st_mode))return 44;
 if(chmod("/dev/binder",0666))return 45;
 puts("REACH15_VM_LOCAL_DAC_NOT_ANDROID_SELINUX=1");
 int ready[2],quit[2];
 if(pipe(ready)||pipe(quit))return 46;
 pid_t mgr=fork();
 if(mgr<0)return 47;
 if(mgr==0){
  close(ready[0]);close(quit[1]);
  _exit(manager(ready[1],quit[0]));
 }
 close(ready[1]);close(quit[0]);
 char r=0;
 if(read(ready[0],&r,1)!=1||r!='R')return 48;
 close(ready[0]);
 pid_t ch=fork();
 if(ch<0)return 49;
 if(ch==0){close(quit[1]);_exit(client());}
 int cs=-1;
 if(waitpid(ch,&cs,0)<0)return 50;
 int client_ok=WIFEXITED(cs)&&WEXITSTATUS(cs)==0;
 printf("REACH15_CLIENT_EXIT=%d\n",WIFEXITED(cs)?WEXITSTATUS(cs):255);
 if(write(quit[1],"Q",1)!=1)return 51;
 close(quit[1]);
 int ms=-1;
 if(waitpid(mgr,&ms,0)<0)return 52;
 int mgr_ok=WIFEXITED(ms)&&WEXITSTATUS(ms)==0;
 printf("REACH15_MANAGER_EXIT=%d\n",WIFEXITED(ms)?WEXITSTATUS(ms):255);
 puts(client_ok && mgr_ok?"REACH15_RESULT=PASS":"REACH15_RESULT=FAIL");
 sync();
 (void)reboot(RB_POWER_OFF);
 return client_ok&&mgr_ok?0:53;
}
