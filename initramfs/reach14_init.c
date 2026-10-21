#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <grp.h>
#include <sys/wait.h>
#include <sys/reboot.h>
#include <unistd.h>
#include <string.h>
struct binder_write_read { uint64_t write_size,write_consumed,write_buffer,read_size,read_consumed,read_buffer; };
#define BINDER_VERSION _IOWR('b',9,int)
#define BINDER_WRITE_READ _IOWR('b',1,struct binder_write_read)
static int guest(void){
  if(getuid()!=10000 || geteuid()!=10000){puts("REACH14_UNPRIV_UID=FAIL");return 31;}
  puts("REACH14_UNPRIV_UID=10000");
  int fd=open("/dev/binder",O_RDWR|O_CLOEXEC);
  printf("REACH14_BINDER_OPEN=%s ERRNO=%d\n",fd>=0?"PASS":"FAIL",fd<0?errno:0);
  if(fd<0)return 32;
  int version=-1; errno=0;
  int rv=ioctl(fd,BINDER_VERSION,&version);
  printf("REACH14_BINDER_VERSION_RET=%d VERSION=%d ERRNO=%d\n",rv,version,errno);
  if(rv || version<=0){close(fd);return 33;}
  struct binder_write_read bwr={0}; errno=0;
  int rc=ioctl(fd,BINDER_WRITE_READ,&bwr);
  int e=errno;
  printf("REACH14_EMPTY_WRITE_READ_RET=%d ERRNO=%d\n",rc,e);
  close(fd);
  puts("REACH14_NO_TRANSACTIONS=1");
  puts("REACH14_NO_RACE=1");
  puts("REACH14_NO_EXPLOIT=1");
  puts("REACH14_NO_ROOT_ESCALATION=1");
  if(rc)return 34;
  puts("REACH14_GUEST_PASS=1");
  return 0;
}
int main(void){
 setvbuf(stdout,NULL,_IONBF,0);
 puts("REACH14_QEMU_PUBLIC_AOSP_ONLY=1");
 mkdir("/dev",0755);
 if(mount("devtmpfs","/dev","devtmpfs",0,NULL)!=0){perror("devtmpfs");return 41;}
 struct stat st;
 if(stat("/dev/binder",&st)!=0){perror("binder");return 42;}
 printf("REACH14_BINDER_IS_CHAR=%d\n",S_ISCHR(st.st_mode)?1:0);
 if(!S_ISCHR(st.st_mode))return 43;
 /* VM test only: PID1 grants guest permissions via chmod, not SELinux. */
 if(chmod("/dev/binder",0666)!=0){perror("chmod");return 44;}
 puts("REACH14_VM_CHMOD_IS_NOT_ANDROID_POLICY=1");
 pid_t ch=fork();
 if(ch<0)return 45;
 if(ch==0){
   if(setgroups(0,NULL)!=0){perror("groups");_exit(46);}
   if(setresgid(10000,10000,10000)!=0){perror("gid");_exit(47);}
   if(setresuid(10000,10000,10000)!=0){perror("uid");_exit(48);}
   _exit(guest());
 }
 int status=0;
 if(waitpid(ch,&status,0)<0)return 49;
 int pass=WIFEXITED(status)&&WEXITSTATUS(status)==0;
 printf("REACH14_CHILD_EXIT=%d\n",WIFEXITED(status)?WEXITSTATUS(status):255);
 puts(pass?"REACH14_RESULT=PASS":"REACH14_RESULT=FAIL");
 sync();
 reboot(RB_POWER_OFF);
 return pass?0:50;
}
