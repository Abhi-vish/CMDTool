from setuptools import setup, find_packages

setup(
    name='CMDHelperTool',
    version='0.1',
    packages=find_packages(),
    entry_points={
        'console_scripts': [
            'cmdhelper = cmdtool.cmd_tool:main'
        ]
    },
    install_requires=[
        'pyperclip'
    ],
    author='Abhi-vish',
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
