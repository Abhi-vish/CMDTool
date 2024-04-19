from setuptools import setup, find_packages

setup(
    name='CMDTool',
    version='0.1',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'cmdtool = cmdtool.cmd_tool:main'
        ]
    },
    install_requires=[
        'pyperclip'
    ],
    author='Abhishek Vishwakarma',
    author_email='iamabhishekvishwakarma7@gmail.com',
    description='A command-line tool for file management and copying to clipboard.',
    license='MIT',
    keywords='command-line tool',
    url='https://github.com/Abhi-vish/CMDTool',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
)
