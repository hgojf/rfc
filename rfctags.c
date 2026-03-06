#include <sys/param.h>

#include <err.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void regdie(int, regex_t *, int, const char *, ...);
static __dead void usage(void);

/*
 * Generates a ctags compatible file for an RFC/STD document, including
 * section names and ABNF rule names as tags.
 *
 * This is written in C because I couldn't figure out how to make it
 * fast enough as a shell script.
 */
int
main(int argc, char *argv[])
{
	FILE *fp;
	regex_t abnf, section;
	size_t linesz;
	ssize_t n;
	int ch, error;
	char *line;
	const char *filename;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	filename = argv[0];

	if ((fp = fopen(filename, "r")) == NULL)
		err(1, "%s", filename);

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	if ((error = regcomp(&abnf, "^[ \t]*([a-zA-Z][a-zA-Z0-9-]*)[ \t]+=[ \t]+.*$",
	    REG_EXTENDED)) != 0)
		regdie(error, &abnf, 1, "regcomp");
	if ((error = regcomp(&section, "^[ \t]*([0-9]\\.)+[ \t]+([a-zA-Z \t]*)$", REG_EXTENDED)) != 0)
		regdie(error, &section, 1, "regcomp");

	line = NULL;
	linesz = 0;
	while ((n = getline(&line, &linesz, fp)) != -1) {
		regmatch_t match[3];

		if (n != 0 && line[n - 1] == '\n')
			line[n - 1] = '\0';

		if ((error = regexec(&abnf, line, nitems(match), match, 0)) != REG_NOMATCH) {
			char *name;

			if (error != 0)
				regdie(error, &abnf, 1, "regexec");

			if ((name = strndup(&line[match[1].rm_so],
					    match[1].rm_eo - match[1].rm_so)) == NULL)
				err(1, NULL);

			if (printf("%s %s /^%s$/\n", name, filename,
				   line) < 0)
				err(1, "printf");

			free(name);
		}
		else if ((error = regexec(&section, line, nitems(match), match, 0)) != REG_NOMATCH) {
			char *section_name, *sp;

			if (error != 0)
				regdie(error, &section, 1, "regexec");

			if ((section_name = strdup(&line[match[2].rm_so])) == NULL)
				err(1, NULL);

			/*
			 * Tag names can't have whitespace in them, so use
			 * underscores like mandoc(1) does.
			 */
			for (sp = section_name; *sp != '\0'; sp++)
				if (*sp == ' ' || *sp == '\t')
					*sp = '_';

			if (printf("%s %s /^%s$/\n", section_name, filename,
				   line) < 0)
				err(1, "printf");

			free(section_name);
		}
	}
	if (ferror(fp))
		err(1, "getline");

	fclose(fp);
	free(line);
	regfree(&abnf);
	regfree(&section);
}

static void
regdie(int error, regex_t *reg, int ex, const char *fmt, ...)
{
	size_t len;
	va_list ap;
	char buf[128], *bufp;

	va_start(ap, fmt);

	len = regerror(error, reg, buf, sizeof(buf));
	bufp = buf;
	if (len > sizeof(buf)) {
		char *b;

		/*
		 * This gets leaked but we are dying anyways.
		 */
		if ((b = malloc(len)) != NULL) {
			regerror(error, reg, b, len);
			bufp = b;
		}
	}

	fprintf(stderr, "%s", getprogname());

	if (fmt != NULL) {
		fprintf(stderr, ": ");
		vfprintf(stderr, fmt, ap);
	}

	fprintf(stderr, ": %s\n", bufp);
	exit(ex);
}

static void
usage(void)
{
	fprintf(stderr, "usage: rfctags file\n");
	exit(2);
}
