from setuptools import setup, find_packages

setup(
    name='CMDHelpMeTool',
    version='0.2',
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
    license='MIT',
    keywords='command-line tool'
)
