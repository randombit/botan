# Sphinx configuration file

import sys, os

# Avoid useless botan_version.pyc (Python 2.6 or higher)
if 'dont_write_bytecode' in sys.__dict__:
    sys.dont_write_bytecode = True

sys.path.insert(0, os.path.join(os.pardir, os.pardir, os.pardir))

import sphinx
import botan_version

def check_for_tag(tag):
    # Nasty hack :(
    try:
        opt_t = sys.argv.index('-t')
        opt_tag = sys.argv.index(tag)
        return opt_t + 1 == opt_tag
    except ValueError:
        return False

is_website_build = check_for_tag('website')

needs_sphinx = '1.1'

extensions = ['sphinx.ext.extlinks']

templates_path = ['templates']

files_dir = 'https://botan.randombit.net/releases'

extlinks = {
    'wikipedia': ('https://en.wikipedia.org/wiki/%s', ''),
    'botan-devel': ('https://lists.randombit.net/pipermail/botan-devel/%s.html', None),

    'cve': ('https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-%s', 'CVE-'),

    'tgz': (files_dir + '/Botan-%s.tgz', 'tar/gz for '),
    'tgz_sig': (files_dir + '/Botan-%s.tgz.asc', 'tar/gz sig '),

    'installer_x86_32': (files_dir + '/win32/botan-%s-x86_32.exe', 'x86-32 '),
    'installer_x86_64': (files_dir + '/win32/botan-%s-x86_64.exe', 'x86-64 '),

    'installer_sig_x86_32': (files_dir + '/win32/botan-%s-x86_32.exe.asc', None),
    'installer_sig_x86_64': (files_dir + '/win32/botan-%s-x86_64.exe.asc', None),
}

source_suffix = '.rst'

source_encoding = 'utf-8-sig'

master_doc = 'contents'

project = u'botan'
copyright = u'2000-2017, The Botan Authors'

version = '%d.%d' % (botan_version.release_major, botan_version.release_minor)

release = '%d.%d.%d' % (botan_version.release_major,
                        botan_version.release_minor,
                        botan_version.release_patch)

#today = ''
today_fmt = '%Y-%m-%d'

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = []

# The reST default role (used for this markup: `text`) to use for all documents.
#default_role = None

# If true, '()' will be appended to :func: etc. cross-reference text.
add_function_parentheses = False

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
#add_module_names = True

# If true, sectionauthor and moduleauthor directives will be shown in the
# output. They are ignored by default.
#show_authors = False

highlight_language = 'cpp'

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# A list of ignored prefixes for module index sorting.
#modindex_common_prefix = []


# -- Options for HTML output ---------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.

try:
    # On Arch this is python-sphinx_rtd_theme
    import sphinx_rtd_theme
    html_theme = "sphinx_rtd_theme"
    html_theme_path = [sphinx_rtd_theme.get_html_theme_path()]
except ImportError as e:
    html_theme = 'agogo'
    html_theme_path = []
    print("Ignoring ImportError and using old theme")

# The name for this set of Sphinx documents.  If None, it defaults to
# "<project> v<release> documentation".
html_title = 'Botan'

# A shorter title for the navigation bar.  Default is the same as html_title.
#html_short_title = None

# The name of an image file (relative to this directory) to place at the top
# of the sidebar.
#html_logo = None

# The name of an image file (within the static path) to use as favicon of the
# docs.  This file should be a Windows icon file (.ico) being 16x16 or 32x32
# pixels large.
#html_favicon = None

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = []

# If not '', a 'Last updated on:' timestamp is inserted at every page bottom,
# using the given strftime format.
html_last_updated_fmt = '%Y-%m-%d'

# If true, SmartyPants will be used to convert quotes and dashes to
# typographically correct entities.
#html_use_smartypants = True

# Custom sidebar templates, maps document names to template names.
#html_sidebars = {}

# Additional templates that should be rendered to pages, maps page names to
# template names.
#html_additional_pages = {}

# If false, no module index is generated.
#html_domain_indices = True

# If false, no index is generated.
#html_use_index = True

# If true, the index is split into individual pages for each letter.
#html_split_index = False

# If true, links to the reST sources are added to the pages.
#html_show_sourcelink = True

# If true, "Created using Sphinx" is shown in the HTML footer. Default is True.
html_show_sphinx = False

# If true, "(C) Copyright ..." is shown in the HTML footer. Default is True.
html_show_copyright = False

# If true, an OpenSearch description file will be output, and all pages will
# contain a <link> tag referring to it.  The value of this option must be the
# base URL from which the finished HTML is served.
if is_website_build:
    html_use_opensearch = 'https://botan.randombit.net/'
else:
    html_use_opensearch = ''

# This is the file name suffix for HTML files (e.g. ".xhtml").
#html_file_suffix = None

# Output file base name for HTML help builder.
htmlhelp_basename = 'botandoc'

# -- Options for LaTeX output --------------------------------------------------

# Various latex options, e.g.,
# paper size option of the document class ('a4paper' or 'letterpaper'), default 'letterpaper'
latex_elements = {
  'papersize': 'a4paper',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author, documentclass [howto/manual]).
latex_documents = [
  ('contents', 'botan.tex', u'Botan Reference Manual',
   u'Jack Lloyd \\and Daniel Neus \\and Ren\u00e9 Korthaus \\and Juraj Somorovsky \\and Tobias Niemann', 'manual'),
]

# The name of an image file (relative to this directory) to place at the top of
# the title page.
#latex_logo = None

# For "manual" documents, if this is true, then toplevel headings are parts,
# not chapters.
#latex_use_parts = False

# If true, show page references after internal links.
latex_show_pagerefs = False

# If true, show URL addresses after external links.
latex_show_urls = 'inline'

# Additional stuff for the LaTeX preamble.
#latex_preamble = ''

# Documents to append as an appendix to all manuals.
#latex_appendices = []

# If false, no module index is generated.
latex_domain_indices = False

