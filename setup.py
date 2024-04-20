from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='CMDHelpMeTool',
    version='0.3.6',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'helpme = CMDHelpMeTool.cmd_tool:main'
        ]
    },
    install_requires=[
        'pyperclip'
    ],
    author='Abhi-vish',
    author_email='iamabhishekvishwakarma7@gmail.com',
    description='A command-line tool for file management and copying to clipboard.',
    long_description=long_description,
    long_description_content_type="text/markdown",  # Specify content type as Markdown
    license='MIT',
    keywords='command-line tool'
)
