local lspconfig = require 'lspconfig'

lspconfig.pyright.setup{
	cmd = {"pyright-langserver", "--stdio"};
	filetypes = {"python"};
	root_dir = lspconfig.util.root_pattern(".git", "setup.py",  "setup.cfg", "pyproject.toml", "requirements.txt");
	settings = {
	analysis = { autoSearchPaths= true; };
	pyright = { useLibraryCodeForTypes = true; };
	};
	-- The following before_init function can be removed once https://github.com/neovim/neovim/pull/12638 is merged
	before_init = function(initialize_params)
		initialize_params['workspaceFolders'] = {{
			name = 'workspace',
			uri = initialize_params['rootUri']
		}}
	end
}
