# Documentation Resources

This directory contains comprehensive documentation for implementing the LLMNR and mDNS disabling security measures in Active Directory environments.

## Available Documentation Formats

### HTML Guide
- [disable_LLMNR_mDNS_guide.html](disable_LLMNR_mDNS_guide.html) - Interactive HTML guide that can be viewed in any web browser

### Markdown Guides (PDF Compatible)
- [Disabling_LLMNR_mDNS_Guide.md](Disabling_LLMNR_mDNS_Guide.md) - Step-by-step guide with screenshot placeholders
- [Comprehensive_LLMNR_mDNS_Guide.md](Comprehensive_LLMNR_mDNS_Guide.md) - Comprehensive guide with additional technical details

### Change Documentation
- [CHANGELOG.md](CHANGELOG.md) - List of changes made to the scripts and documentation

## Creating PDF Documents

You can easily convert the markdown files to PDF format using various tools:

### Using Pandoc (Command Line)

1. Install [Pandoc](https://pandoc.org/installing.html)
2. Run the following command:
   ```
   pandoc -s Disabling_LLMNR_mDNS_Guide.md -o Disabling_LLMNR_mDNS_Guide.pdf
   ```

### Using Visual Studio Code

1. Install Visual Studio Code
2. Install the "Markdown PDF" extension
3. Open the markdown file
4. Click the "Export (Ctrl+Shift+P)" command
5. Select "Markdown PDF: Export (pdf)"

### Using Microsoft Word

1. Open Microsoft Word
2. Click File > Open and select the markdown file
3. Word will convert the markdown to a formatted document
4. Save as PDF using File > Save As > PDF

## Inserting Screenshots

Before converting to PDF, you should replace the image placeholders with actual screenshots:

1. Take screenshots of each step in your Active Directory environment
2. Save them in the `/images` directory following the naming convention described in the placeholder file
3. The markdown files already contain links to these images which will be automatically included in your PDF

## Customization

Feel free to customize these documents to match your organization's requirements and branding:

- Add your organization's logo
- Include specific Active Directory structure information
- Modify or add specific steps relevant to your environment