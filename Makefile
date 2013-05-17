PAGE_MARGIN=2.5cm

readme: report-css report-html report-pdf

report-css: assets/sass/styles.sass
	compass compile

report-html: report.md
	kramdown --template template.html.erb report.md > report.html

report-pdf: report.html
	wkhtmltopdf -L $(PAGE_MARGIN) -R $(PAGE_MARGIN) -T $(PAGE_MARGIN) -B $(PAGE_MARGIN) report.html report.pdf
