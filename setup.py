from setuptools import setup, find_packages

setup(
    name='my-cmd-tool',
    version='1.0',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'my-cmd-tool = my_cmd_tool.cmd_tool:main'
        ]
    },
    install_requires=[
        'pyperclip'
    ],
    author='Your Name',
    author_email='your.email@example.com',
    description='A command-line tool for file management and copying to clipboard.',
    license='MIT',
    keywords='command-line tool',
    url='https://github.com/yourusername/my-cmd-tool'
)
