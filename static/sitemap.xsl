<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:sitemap="http://www.sitemaps.org/schemas/sitemap/0.9">
    <xsl:output method="html" indent="yes" encoding="UTF-8" />

    <xsl:template match="/">
        <html>
            <head>
                <title>Hypeblog9jatv Sitemap</title>
                <style type="text/css">
                    body {
                        font-family: Arial, sans-serif;
                        background-color: #ffffff;
                        color: #333;
                        line-height: 1.6;
                        margin: 20px;
                    }
                    h1 {
                        color: #007BFF;
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 20px;
                    }
                    th, td {
                        padding: 12px;
                        text-align: left;
                        border-bottom: 1px solid #ddd;
                    }
                    tr:nth-child(even) {
                        background-color: #f2f2f2;
                    }
                    tr:hover {
                        background-color: #e9ecef;
                    }
                    a {
                        color: #007BFF;
                        text-decoration: none;
                    }
                    a:hover {
                        text-decoration: underline;
                    }
                </style>
            </head>
            <body>
                <h1>Hypeblog9jatv Sitemap</h1>
                <table>
                    <thead>
                        <tr>
                            <th>URL</th>
                            <th>Last Modified</th>
                        </tr>
                    </thead>
                    <tbody>
                        <xsl:for-each select="sitemap:sitemapindex/sitemap:sitemap">
                            <tr>
                                <td>
                                    <a href="{sitemap:loc}">
                                        <xsl:value-of select="sitemap:loc" />
                                    </a>
                                </td>
                                <td>
                                    <xsl:value-of select="sitemap:lastmod" />
                                </td>
                            </tr>
                        </xsl:for-each>
                    </tbody>
                </table>
            </body>
        </html>
    </xsl:template>
</xsl:stylesheet>