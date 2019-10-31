#include <iostream>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <string.h>

using namespace std;

void getline(char *linedata, int fd);
void updateMyShadow(const char* username, bool createLine);
int drop_priv_temp();
int drop_priv_perm();
int restore_priv();

int main(int argc, char ** argv)
{
    char usage[] = "usage: ";
    drop_priv_temp();
    uid_t ruid, euid, suid;
    getresuid(&ruid, &euid, &suid);

    if (ruid == 0){
        // root user
        if (argc == 1){
            updateMyShadow("root", true);
        } else {
            for (int i = 1; i < argc; i++){
                updateMyShadow(argv[i], false);
            }
        }
    } else if (argc == 1){
        // ordinary user
        const passwd* p_userinfo = getpwuid(ruid);
        if (p_userinfo)
            updateMyShadow(p_userinfo->pw_name, true);
        else
            printf("there is no username for this guy: %u!", ruid);
    }
    return 0;
}


void getline(char *linedata, int fd){
    int i = 0;
    linedata[0] = '\0';
    char tmp[2];
    while (read(fd, tmp, 1) > 0 && strcmp(tmp, "\n") != 0){
        linedata[i++] = tmp[0];
    }
    if (!linedata[0]){
        return;
    }
//    linedata[i++]='\n';
    linedata[i]='\0';
}

void updateMyShadow(const char* username, bool isOwner){
    time_t now;
    struct tm *tm_now ;
    time(&now);
    tm_now = localtime(&now) ;
    char timestr[25];
    sprintf(timestr, " %d-%d-%d %d:%d:%d\n",
    tm_now->tm_year+1900, tm_now->tm_mon+1, tm_now->tm_mday, tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec) ;

    char tmp_cmp[25];
    strcpy(tmp_cmp, username);
    strcat(tmp_cmp, ":");
    restore_priv();
    int fd = open("./myShadow", O_RDONLY);
    int fdnew = open("./tmpShadow", O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP);
    //chown()
//    for
    char linedata[50];
    bool hasChanged = false;
    getline(linedata, fd);
    while (linedata[0])
    {
        if (!hasChanged && strncmp(linedata, tmp_cmp, strlen(tmp_cmp))==0)
        {
            write(fdnew, tmp_cmp, strlen(tmp_cmp));
            write(fdnew, timestr, strlen(timestr));
//            write(fdnew, "\n", 1);
            hasChanged = true;
        }else{
            write(fdnew, linedata, strlen(linedata));
            write(fdnew, "\n", 1);
        }
        getline(linedata, fd);
    }
    if (!hasChanged && isOwner){
        write(fdnew, tmp_cmp, strlen(tmp_cmp));
        write(fdnew, timestr, strlen(timestr));
//        write(fdnew, "\n", 1);
    }
    printf("clean files\n");
    remove("./myShadow");
    rename("./tmpShadow", "./myShadow");
    chown("./myShadow", 0, 0);
    close(fd);
    close(fdnew);
    drop_priv_perm();
}


int drop_priv_temp(){
    // set effective uid to new_uid, and save old effective uid to saved-set uid
    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) <0)
        return -1;
    if (setresuid(ruid, ruid, euid) < 0)
        return -1;
    return 0;
}

int drop_priv_perm(){
    // getuid: get real user id
    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) <0)
        return -1;
    if (setresuid(ruid, ruid, ruid) < 0)
        return -1;
    return 0;
}

int restore_priv(){
    uid_t ruid, euid, suid;
    if (getresuid(&ruid, &euid, &suid) <0)
        return -1;
    if (setresuid(ruid, suid, ruid) < 0)
        return -1;
    return 0;
}
