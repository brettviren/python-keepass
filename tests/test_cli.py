from keepass import cli

def test_parse_args():
    main = cli.Cli(['-a', '-b', '-c', 'open', '-a', '-b', '-c', 'foo'])
    assert main.command_line == [['general', ['-a', '-b', '-c']], 
                                 ['open', ['-a', '-b', '-c', 'foo']]]
