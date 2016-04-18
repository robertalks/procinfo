#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <time.h>

#ifndef	PATH_MAX
  #define PATH_MAX	4096
#endif

#define STR_MAX		256
#define UTIL_MAX	16384

static const char *cmd = "procinfo";
static const char *default_value = "none";

struct procinfo {
	pid_t pid;
	pid_t ppid;
	char dir[PATH_MAX];
	char cmd[STR_MAX];
	char parent_cmd[STR_MAX];
	char exe[PATH_MAX];
	char state;
	unsigned int fds;
	unsigned int threads_count;
	size_t *threads;
	uid_t uid;
	gid_t gid;
	char user[STR_MAX];
	char group[STR_MAX];
	size_t vsz;
	size_t rss;
	time_t pid_ctime;
	time_t pid_mtime;
};

struct procinfo *alloc_struct()
{
	struct procinfo *p;

	p = calloc(1, sizeof(struct procinfo));
	if (!p)
		return NULL;

	p->pid = p->ppid = p->fds = p->threads_count = p->vsz = p->rss = 0;
	p->threads = NULL;

	strncpy(p->dir, default_value, sizeof(p->dir));
	strncpy(p->cmd, default_value, sizeof(p->cmd));
	strncpy(p->parent_cmd, default_value, sizeof(p->parent_cmd));
	strncpy(p->exe, default_value, sizeof(p->exe));
	strncpy(p->user, default_value, sizeof(p->user));
	strncpy(p->group, default_value, sizeof(p->group));

	return p;
}

static void free_struct(struct procinfo *p)
{
	if (p) {
		if (p->threads)
			free(p->threads);
		free(p);
	}
}

static int count_maps_fds(pid_t pid)
{
	FILE *file;
	int i, j;
	char **map = NULL;
	unsigned int count = 0, fds = 0;
	char input[UTIL_MAX];
	char filename[PATH_MAX];

	snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
	file = fopen(filename, "re");
	if (file) {
		map = calloc(UTIL_MAX, sizeof(char *));
		if (map == NULL)
			return -ENOMEM;

		while (fgets(input, UTIL_MAX, file) != NULL) {
			char *pos;

			pos = strstr(input, "/");
			if (pos != NULL) {
				size_t len = strlen(pos);
				if (pos[len - 1] == '\n')
					pos[len - 1] = '\0';
				map[count] = calloc(len - 1, sizeof(char *));
				if (map[count] == NULL)
					return -ENOMEM;
				strcpy(map[count], pos);
				count++;
			}

			if (count >= UTIL_MAX)
				return -EOVERFLOW;
		}
		fclose(file);
	}

	fds = count;
	for(i = 0; i < count; i++) {
		for(j = i + 1; j < count; j++) {
			if (strcmp(map[i], map[j]) == 0) {
				fds--;
				break;
			}
		}
	}

	if (map) {
		for(i = 0; i < count; i++) {
			if (map[i])
				free(map[i]);
		}
		free(map);
	}

	return fds;
}

static int set_procinfo_values(struct procinfo *p)
{
	FILE *file;
	struct stat s;
	char filename[PATH_MAX];
	char dirname[PATH_MAX];
	char input[PATH_MAX];
	struct dirent *dent;
	DIR *srcdir = NULL;
	size_t len = 0;
	int r = 0;
	struct passwd *pw = NULL;
	struct group *gr = NULL;

	if (p->dir == NULL)
		return -1;

	if (stat(p->dir, &s) != 0)
		return -errno;

	p->uid = s.st_uid;
	p->gid = s.st_gid;
	p->pid_ctime = s.st_ctime;
	p->pid_mtime = s.st_mtime;

	if ((pw = getpwuid(p->uid)) != NULL)
		snprintf(p->user, STR_MAX, "%s", pw->pw_name);

	if ((gr = getgrgid(p->gid)) != NULL)
		snprintf(p->group, STR_MAX, "%s", gr->gr_name);

	snprintf(filename, sizeof(filename), "%s/exe", p->dir);
	len = readlink(filename, p->exe, sizeof(p->exe) - 1);
	if (len > 0)
		p->exe[len] = '\0';

	snprintf(filename, sizeof(filename), "%s/status", p->dir);
	file = fopen(filename, "re");
	if (file) {
		while (fgets(input, UTIL_MAX, file) != NULL) {
			char *str = strdup(input);
			
			if (strncmp(str, "Name:", 5) == 0)
				(void) sscanf(str, "Name:\t%s", p->cmd);

			if (strncmp(str, "State:", 6) == 0)
				(void) sscanf(str, "State:\t%c%*[^\n]", &p->state);

			if (strncmp(str, "PPid:", 5) == 0) {
				(void) sscanf(str, "PPid:\t%u", &p->ppid);
				if (p->pid == 1)
					p->ppid = 1;
			}
			free(str);
		}
		fclose(file);
	}

	snprintf(filename, sizeof(filename), "/proc/%u/status", p->ppid);
	file = fopen(filename, "re");
	if (file) {
		while (fgets(input, UTIL_MAX, file) != NULL) {
			char *str = strdup(input);

			if (strncmp(str, "Name:", 5) == 0)
				sscanf(str, "Name:\t%s", p->parent_cmd);

			free(str);
		}
		fclose(file);
	}

	snprintf(filename, sizeof(filename), "%s/smaps", p->dir);
	file = fopen(filename, "re");
	if (file) {
		while (fgets(input, UTIL_MAX, file)) {
			char *str = strdup(input); 
			unsigned long size;

			if (strncmp(str, "Size:", 5) == 0) {
				if (sscanf(str, "Size:\t%lu%*[^\n]", &size) == 1)
					p->vsz += size;
			}

			if (strncmp(str, "Rss:", 4) == 0) {
				if (sscanf(str, "Rss:\t%lu%*[^\n]", &size) == 1)
					p->rss += size;
			}
			free(str);
		}
		fclose(file);
	}

	p->threads_count = 0;
	p->threads = calloc(1, sizeof(size_t));
	if (p->threads == NULL)
		return -ENOMEM;

	snprintf(dirname, sizeof(dirname), "%s/task", p->dir);
	srcdir = opendir(dirname);
	if (srcdir) {
		while ((dent = readdir(srcdir)) != NULL) {
			size_t thread = 0;

			if(strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
				continue;

			if (isdigit(dent->d_name[0]) && dent->d_type == DT_DIR) {
				thread = (size_t) strtol(dent->d_name, NULL, 10);
				if (thread > 0) {
					p->threads[p->threads_count] = thread;
					p->threads_count++;
					p->threads = realloc(p->threads, (p->threads_count + 1) * sizeof(size_t));
				}
			}
		}
		closedir(srcdir);
	}

	// initial value, we need to count ROOT and CWD as 2 FDs
	p->fds = 2;

	snprintf(dirname, sizeof(dirname), "%s/fd", p->dir);
	srcdir = opendir(dirname);
	if (srcdir) {
		while ((dent = readdir(srcdir)) != NULL) {
			if(strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
				continue;

			p->fds++;
		}
		closedir(srcdir);
	}

	if ((r = count_maps_fds(p->pid)) > 0)
		p->fds += r;

	return 0;
}

static char *print_proc_time(time_t time)
{
	char *stime;
	size_t len = 0;

	stime = strdup(ctime(&time));
	len = strlen(stime);
	if (stime[len - 1] == '\n')
		stime[len - 1] = '\0';

	return stime;
}

static int print_proc_info(int pid, char dir[PATH_MAX], struct procinfo *p, int no_full_output)
{
	int i, r = 0;

	p->pid = pid;
	snprintf(p->dir, sizeof(p->dir), "%s", dir);

	if ((r = set_procinfo_values(p)) != 0) {
		(void) fprintf(stderr, "%s: %s\n", cmd, strerror(r));
		return -1;
	}

	if (no_full_output == 1) {
		(void) fprintf(stdout, "PID: %u, ", p->pid);
		(void) fprintf(stdout, "PPID: %u, ", p->ppid);
		(void) fprintf(stdout, "CMD: %s, ", p->cmd);
		(void) fprintf(stdout, "State: %c, ", p->state);
		(void) fprintf(stdout, "VSZ: %zd, ", p->vsz);
		(void) fprintf(stdout, "RSS: %zd", p->rss);
		(void) fprintf(stdout, "\n");
		return 0;
	}

	(void) fprintf(stdout, "--- Process information ---\n");
	
	(void) fprintf(stdout, "PID: %u\n", p->pid);
	(void) fprintf(stdout, "EXE: %s\n", p->exe);
	(void) fprintf(stdout, "CMD: %s\n", p->cmd);
	(void) fprintf(stdout, "PPID: %u (%s)\n", p->ppid, p->parent_cmd);
	(void) fprintf(stdout, "State: %c\n", p->state);
	(void) fprintf(stdout, "Start time: %s\n", print_proc_time(p->pid_ctime));
	(void) fprintf(stdout, "User: %s (UID: %u)\n", p->user, p->uid);
	(void) fprintf(stdout, "Group: %s (GID: %u)\n", p->group, p->gid);
	(void) fprintf(stdout, "VSZ: %zd MB (%zd KB)\n", p->vsz / 1024, p->vsz);
	(void) fprintf(stdout, "RSS: %zd MB (%zd KB)\n", p->rss / 1024, p->rss);
	(void) fprintf(stdout, "Open FDs: %u\n", p->fds);
	(void) fprintf(stdout, "Threads count: %u\n", p->threads_count);
	(void) fprintf(stdout, "Threads: ");
	for(i = 0; i < p->threads_count; i++) {
		if (p->threads[i]) {
			(void) fprintf(stdout, "%zd", p->threads[i]);
			if (p->threads[i] == p->pid)
				(void) fprintf(stdout, " (P)");
		}	
		if (i < p->threads_count - 1)
			(void) fprintf(stdout, ", ");
	}
	(void) fprintf(stdout, "\n");

	return 0;
}

int main(int argc, char *argv[])
{
	pid_t procpid;
	char procdir[PATH_MAX];
	struct stat s;
	struct procinfo *ptr;

	if (argc <= 1) {
		(void) fprintf(stderr, "%s: you must supply the PID number of a process\n", cmd);
		return 1;
	}

	if (!argv[1]) {
		(void) fprintf(stderr, "%s: empty argument", cmd);
		return 1;
	}

	procpid = (pid_t) strtol(argv[1], NULL, 10);
	if (procpid <= 0) {
		(void) fprintf(stderr, "%s: PID cant be 0 or a negative value\n", cmd);
		return 1;
	}

	snprintf(procdir, sizeof(procdir), "/proc/%d", procpid);
	if (stat(procdir, &s) != 0) {
		if (errno == ENOENT)
			(void) fprintf(stderr, "%s: no such process\n", cmd);
		else
			(void) fprintf(stderr, "%s: %s\n", cmd, strerror(errno));

		return errno;
	}

	ptr = alloc_struct();
	if (!ptr) {
		(void) fprintf(stderr, "%s: failed to allocate memory for structure.\n", cmd);
		return ENOMEM;
	}

	print_proc_info(procpid, procdir, ptr, 0);

	free_struct(ptr);

	return 0;
}
