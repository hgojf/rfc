/*
 * Copyright (c) 2026 Henry Ford <fordhenry2299@gmail.com>

 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/param.h>

#include <err.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void regdie(int, regex_t *, int, const char *, ...);
static char *regstrdup(const char *, regmatch_t *);
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
	size_t lineno, linesz;
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

	if (argc == 0) {
		filename = "stdin";
		fp = stdin;
	}
	else {
		if (argc != 1)
			usage();
		filename = argv[0];
		if ((fp = fopen(filename, "r")) == NULL)
			err(1, "%s", filename);
	}

	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");

	if ((error = regcomp(&abnf, "^[ \t]*([a-zA-Z][a-zA-Z0-9-]*)[ \t]+=[ \t]+.*$",
	    REG_EXTENDED)) != 0)
		regdie(error, &abnf, 1, "regcomp");
	if ((error = regcomp(&section, "^[ \t]*([0-9](\\.[0-9])*)\\.[ \t]+(.*)$", REG_EXTENDED)) != 0)
		regdie(error, &section, 1, "regcomp");

	line = NULL;
	lineno = 0;
	linesz = 0;
	while ((n = getline(&line, &linesz, fp)) != -1) {
		regmatch_t match[4];

		if (n != 0 && line[n - 1] == '\n')
			line[n - 1] = '\0';

		if ((error = regexec(&abnf, line, nitems(match), match, 0)) != REG_NOMATCH) {
			char *name;

			if (error != 0)
				regdie(error, &abnf, 1, "regexec");

			if ((name = regstrdup(line, &match[1])) == NULL)
				err(1, NULL);

			if (printf("%s %s %zu\n", name, filename,
				   lineno + 1) < 0)
				err(1, "printf");

			free(name);
		}
		else if ((error = regexec(&section, line, nitems(match), match, 0)) != REG_NOMATCH) {
			char *section_name, *section_number, *sp;

			if (error != 0)
				regdie(error, &section, 1, "regexec");

			if ((section_name = regstrdup(line, &match[3])) == NULL)
				err(1, NULL);

			/*
			 * Tag names can't have whitespace in them, so use
			 * underscores like mandoc(1) does.
			 */
			for (sp = section_name; *sp != '\0'; sp++)
				if (*sp == ' ' || *sp == '\t')
					*sp = '_';

			if (printf("%s %s %zu\n", section_name, filename,
				   lineno + 1) < 0)
				err(1, "printf");

			free(section_name);

			if ((section_number = regstrdup(line, &match[1])) == NULL)
				err(1, NULL);
			if (printf("%s %s %zu\n", section_number, filename,
				   lineno + 1) < 0)
				err(1, "printf");
			free(section_number);
		}

		if (lineno == SIZE_MAX - 2)
			errx(1, "file too long");
		lineno++;
	}
	if (ferror(fp))
		err(1, "getline");

	if (fp != stdin)
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

/*
 * Duplicate the portion of s described by mp.
 */
static char *
regstrdup(const char *s, regmatch_t *mp)
{
	return strndup(&s[mp->rm_so], mp->rm_eo - mp->rm_so);
}

static void
usage(void)
{
	fprintf(stderr, "usage: rfctags [file]\n");
	exit(2);
}
