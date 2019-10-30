/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package inplacedynamic;

import java.awt.event.InputEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.KeyStroke;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import docking.action.ToolBarData;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import resources.ResourceManager;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.EXAMPLES,
	shortDescription = "Plugin short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class inPlaceDynamicPlugin extends ProgramPlugin {

	private ARM_Emulator_Provider provider;
	private X86_Emulator_Provider x86_provider;
	private Plugin plugin;
	private EMULATORS currentEmulator;
	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	
	
	//TODO: add input from user that shows the current function on the inplace window
	//TODO: get current program instruction to run and display in emulator
	public inPlaceDynamicPlugin(PluginTool tool) {
		super(tool, true, true);
		this.plugin = this;
		createActions();
	}

	@Override
	public void init() {
		super.init();

		// TODO: Acquire services if necessary
	}
	
	@Override
	// This no longer works, fixit
	protected void locationChanged(ProgramLocation location) {
		if (location == null || provider == null) {
			return;
		}
		//Memory mem = currentProgram.getMemory();
		//System.out.println(String.format("M " + mem.getAllInitializedAddressSet().toString() + mem.getMaxAddress().toString()));
		//provider.setLocation(currentLocation, currentProgram);
		x86_provider.setLocation(currentLocation, currentProgram);
	}
	
	private void createActions() {
		DockingAction dynamicWindow = new DockingAction("In Place Dynamic Analyzer", name) {
			@Override
			public void actionPerformed(ActionContext context) {
				//this is a very hacky and cheap way to do this
				hack h = new hack();
				h.set();
				String pluginName = getName();
				switch(currentEmulator) {
					case ARM:
						provider = new ARM_Emulator_Provider(plugin, pluginName);
						provider.setLocation(currentLocation, currentProgram);
						break;
					case ARM64:
						Msg.showInfo(getClass(), null, "Emulator", "Not yet supported");
						break;
					case M68K:
						Msg.showInfo(getClass(), null, "Emulator", "Not yet supported");
						break;
					case MIPS:
						Msg.showInfo(getClass(), null, "Emulator", "Not yet supported");
						break;
					case SPARC:
						Msg.showInfo(getClass(), null, "Emulator", "Not yet supported");
						break;
					case X86:
						Msg.showInfo(getClass(), null, "Emulator", "Not yet supported");
						break;
					case X86_64:
						x86_provider = new X86_Emulator_Provider(plugin, pluginName);
						x86_provider.setLocation(currentLocation, currentProgram);
						break;
					default:
						break;
				}
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return currentProgram != null;
			}
		};
		dynamicWindow.setToolBarData(new ToolBarData(ResourceManager.loadImage("images/play1.png"), "Dynetics"));
		dynamicWindow.setKeyBindingData(new KeyBindingData( KeyStroke.getKeyStroke('E', InputEvent.CTRL_DOWN_MASK ) ));
		dynamicWindow.setMenuBarData(new MenuData(new String[] { "Dynetics", "In Place Dynamic Analysis" }, "Dynetics"));
		tool.addAction(dynamicWindow);
	}
	
	// this is a hacky way to get 
	private class hack extends GhidraScript{

		@Override
		protected void run() throws Exception {
			// TODO Auto-generated method stub
		}
		
		public void set() {
			List<EMULATORS> emulators = new ArrayList<EMULATORS>();
			for(EMULATORS e : EMULATORS.values()) {
				emulators.add(e);
			}
			
			try {
				currentEmulator = askChoice("Choice", "Please choose one", emulators, null);
			} catch (CancelledException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}
	
	public enum EMULATORS {
		ARM {
		  	public String toString() {
		    	return "ARM32";
		  	}
		},
		ARM64 {
		  	public String toString() {
		      	return "ARM64 (ARMV8)";
		  	}
		},
		M68K {
		  	public String toString() {
		      	return "M68K";
		  	}
		},
		MIPS {
		  	public String toString() {
		      	return "MIPS";
		  	}
		},
		SPARC {
		  	public String toString() {
		      	return "SPARC";
		  	}
		},
		X86 {
		  	public String toString() {
		      	return "X86";
		  	}
		},
		X86_64 {
		  	public String toString() {
		      	return "X86_64";
		  	}
		}
	}
}















