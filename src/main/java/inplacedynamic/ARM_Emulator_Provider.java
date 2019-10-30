package inplacedynamic;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;

import javax.swing.*;
import javax.swing.border.BevelBorder;
import javax.swing.border.TitledBorder;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import resources.Icons;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;


public class ARM_Emulator_Provider extends ComponentProviderAdapter{
	private JPanel panel;
	private DockingAction action;
	private JTextArea emulator;
	private ARM_Emulator_Provider provider;
	private Address currentAddress;
	private long functionLen;
	private FunctionManager functionManager;
	private Function currentFunction;
	private ARM_emulator arm;
	private JTextArea stack;
	public JTextArea labelR0 = new JTextArea();
	public JTextArea labelR1 = new JTextArea();
	public JTextArea labelR2 = new JTextArea();
	public JTextArea labelR3 = new JTextArea();
	public JTextArea labelR4 = new JTextArea();
	public JTextArea labelR5 = new JTextArea();
	public JTextArea labelR6 = new JTextArea();
	public JTextArea labelR7 = new JTextArea();
	public JTextArea labelR8 = new JTextArea();
	public JTextArea labelR9 = new JTextArea();
	public JTextArea labelR10 = new JTextArea();
	public JTextArea labelR11 = new JTextArea();
	public JTextArea labelR12 = new JTextArea();
	public JTextArea labelSP = new JTextArea();
	public JTextArea labelLR = new JTextArea();
	public JTextArea labelPC = new JTextArea();
	public JTextArea labelCPSR = new JTextArea();
	public JTextArea base = new JTextArea();
	public JTextArea instru = new JTextArea();
	public JTextArea baseLen = new JTextArea();
	public JTextArea memoryView = new JTextArea();
	public JTextArea memoryLocation = new JTextArea();
	public JTextArea memoryContents = new JTextArea();
	private FlatProgramAPI api;

	public ARM_Emulator_Provider(Plugin plugin, String owner) {
		super(plugin.getTool(), owner, owner);
		mkPanel();
		mkActions();
		tool = plugin.getTool();
		this.provider = this;
	}

	private void mkPanel(){
		TitledBorder border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R0");
		labelR0.setBorder(border);
		labelR0.setEnabled(true);
		labelR0.setText("0x0000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R1");
		labelR1.setEnabled(true);
		labelR1.setBorder(border);
		labelR1.setText("0x0000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R2");
		labelR2.setEnabled(true);
		labelR2.setBorder(border);
		labelR2.setText("0x0000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R3");
		labelR3.setEnabled(true);
		labelR3.setBorder(border);
		labelR3.setText("0x0000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R4");
		labelR4.setEnabled(true);
		labelR4.setBorder(border);
		labelR4.setText("0x0000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R5");
		labelR5.setEnabled(true);
		labelR5.setBorder(border);
		labelR5.setText("0x0000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R6");
		labelR6.setEnabled(true);
		labelR6.setBorder(border);
		labelR6.setText("0x0000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R7");
		labelR7.setEnabled(true);
		labelR7.setBorder(border);
		labelR7.setText("0x0000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R8");
		labelR8.setEnabled(true);
		labelR8.setBorder(border);
		labelR8.setText("0x0000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R9");
		labelR9.setEnabled(true);
		labelR9.setBorder(border);
		labelR9.setText("0x0000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R10");
		labelR10.setEnabled(true);
		labelR10.setBorder(border);
		labelR10.setText("0x0000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R11");
		labelR11.setEnabled(true);
		labelR11.setBorder(border);
		labelR11.setText("0x0000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "R12");
		labelR12.setEnabled(true);
		labelR12.setBorder(border);
		labelR12.setText("0x0000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "SP");
		labelSP.setEnabled(true);
		labelSP.setBorder(border);
		labelSP.setText("0x0800");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "LR");
		labelLR.setEnabled(true);
		labelLR.setBorder(border);
		labelLR.setText("0x0000");
	
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "PC");
		labelPC.setEnabled(true);
		labelPC.setBorder(border);
		labelPC.setText("0x0000");

		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "CPSR");
		labelCPSR.setEnabled(true);
		labelCPSR.setBorder(border);
		labelCPSR.setText("0x0000");

		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "BASE");
		base.setEnabled(true);
		base.setBorder(border);
		base.setText("0x10000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "BASE_SIZE");
		baseLen.setEnabled(true);
		baseLen.setBorder(border);
		baseLen.setText("0x200000");
		
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "NEXT INSTRUCTION");
		instru.setEnabled(true);
		instru.setBorder(border);
		instru.setText("00");

		JPanel insidePanel = new JPanel();
		insidePanel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
		insidePanel.setLayout(new BoxLayout(insidePanel, BoxLayout.Y_AXIS));
		insidePanel.add(labelR0);
		insidePanel.add(labelR1);
		insidePanel.add(labelR2);
		insidePanel.add(labelR3);
		insidePanel.add(labelR4);
		insidePanel.add(labelR5);
		insidePanel.add(labelR6);
		insidePanel.add(labelR7);
		insidePanel.add(labelR8);
		insidePanel.add(labelR9);
		insidePanel.add(labelR10);
		insidePanel.add(labelR11);
		insidePanel.add(labelR12);
		insidePanel.add(labelSP);
		insidePanel.add(labelLR);
		insidePanel.add(labelPC);
		insidePanel.add(labelCPSR);
		insidePanel.add(base);
		insidePanel.add(baseLen);

		panel = new JPanel();
		panel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
		panel.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.BOTH;
		
		c.gridx = 0;
		c.gridy = 0;
		c.weightx = 0.50;
		c.weighty = 0;
		//c.gridheight = 1;
		panel.add(instru, c);
		
		c.gridy = 1;
		c.weighty = 0.90;
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "DEBUG VIEW");
		border.setTitleColor(Color.WHITE);
		emulator = new JTextArea();
		emulator.setBackground(Color.decode("#272822"));
		emulator.setForeground(Color.decode("#E6DB74"));
		emulator.setBorder(border);
		emulator.setEditable(false);
		JScrollPane scroll = new JScrollPane (emulator, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		panel.add(scroll, c);
		
//==============================================
		
		c.gridx = 1;
		c.weightx = 0.15;
		c.gridy = 0;
		c.weighty = 0;
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "MEMORY LOCATION");
		memoryLocation.setEnabled(true);
		memoryLocation.setBorder(border);
		memoryLocation.setText("0xffffffff");
		panel.add(memoryLocation, c);
		
		c.gridx = 2;
		c.weightx = 0.15;
		c.gridy = 0;
		c.weighty = 0;
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "MEMORY CONTENTS");
		memoryContents.setEnabled(true);
		memoryContents.setBorder(border);
		memoryContents.setText("00 00 00 00");
		panel.add(memoryContents, c);
		
		c.gridx = 1;
		c.gridy = 1;
		c.weighty = 0;
		c.gridwidth = 2;
		memoryView.setBackground(Color.decode("#272822"));
		memoryView.setForeground(Color.decode("#E6DB74"));
		memoryView.setEditable(false);
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "MEMORY");
		border.setTitleColor(Color.WHITE);
		memoryView.setBorder(border);
		JScrollPane memoryScroll = new JScrollPane (memoryView, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		panel.add(memoryScroll, c);
		
		
//==============================================
		
		c.gridx = 3;
		c.gridy = 0;
		c.weightx = 0.10;
		c.gridheight = 2;
		c.gridwidth = 1;
		stack = new JTextArea();
		stack.setBackground(Color.decode("#272822"));
		stack.setForeground(Color.decode("#E6DB74"));
		stack.setEditable(false);
		border = new TitledBorder(new BevelBorder(BevelBorder.LOWERED), "STACK");
		border.setTitleColor(Color.WHITE);
		stack.setBorder(border);
		JScrollPane stackScroll = new JScrollPane (stack, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		panel.add(stackScroll, c);
		
//==============================================
		
		c.gridx = 4;
		c.gridy = 0;
		c.weightx = 0.10;
		c.gridheight = 2;
		JScrollPane lablesScroll = new JScrollPane (insidePanel, ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED, 
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
		panel.add(lablesScroll, c);

		setVisible(true);
	}
	
	public void addText(String newText) {
		emulator.append(newText + "\n\r");
	}
	
	public void setStack(String st) {
		stack.append(st);
	}
	
	public void clearStack() {
		stack.setText("");
	}
	
	private void mkActions() {
		action = new DockingAction("Get Memory Address", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				Dimension d = instru.getSize();
				emulator.append(String.format("%d, %d", d.width, d.height));
				getMemoryContents();
			}
		};
		
		action.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
		
		action = new DockingAction("Set Memory Address", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				setMemoryContents();
			}
		};
		
		action.setToolBarData(new ToolBarData(Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
		
		action = new DockingAction("Set Bytes", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if(arm != null) {
					try {
						String instruction = instru.getText();
						byte [] newInstruction = {(byte) Integer.parseInt(instruction.substring(0, 2), 16), 
							(byte) Integer.parseInt(instruction.substring(3, 5), 16),
							(byte) Integer.parseInt(instruction.substring(6, 8), 16),
							(byte) Integer.parseInt(instruction.substring(9, 11), 16)};
							api.start();
							Address nextAddress = api.toAddr(arm.getPC());
							api.clearListing(nextAddress);
							api.setBytes(nextAddress, newInstruction);
							api.disassemble(nextAddress);
							api.end(true);
							// not sure if we need to auto analyze 
							//api.analyzeChanges(currentFunction.getProgram());
					} catch (MemoryAccessException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (CancelledException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					} catch (NumberFormatException e) {
						Msg.showInfo(getClass(), null, "OPPS", String.format("Please format new instruction as: 01 02 03 04\n %s", e));
					} catch (StringIndexOutOfBoundsException e) {
						Msg.showInfo(getClass(), null, "OPPS", String.format("Please format new instruction as: 01 02 03 04\n %s", e));
					}
				}
			}
		};
		
		action.setToolBarData(new ToolBarData(Icons.REFRESH_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
		
		action = new DockingAction("Show Memory", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				updateMemory();
			}
		};
		
		action.setToolBarData(new ToolBarData(Icons.EXPAND_ALL_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
		
		action = new DockingAction("Next Instruction", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if(arm != null) {
					byte[] code;
					try {
						code = api.getBytes(api.toAddr(arm.getPC()), 4);
						setCurrentAddress(api.toAddr(arm.step_arm(code)), currentFunction.getProgram());
						code = api.getBytes(api.toAddr(arm.getPC()), 4);
						instru.setText(String.format("%02x %02x %02x %02x", code[0], code[1], code[2], code[3]));
						//updateMemory();
					} catch (MemoryAccessException e) {
						Msg.showInfo(getClass(), null, "OPPS", e);
					}
					if(arm.getStatus() != 1) {
						arm = null;
						Msg.showInfo(getClass(), null, "Finished", "Program Emulation Finished");
					}
				}
			}
		};
		
		action.setToolBarData(new ToolBarData(Icons.ARROW_DOWN_RIGHT_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
		
		action = new DockingAction("Run", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				if(arm != null) {
					setCurrentAddress(api.toAddr(arm.run_arm()), currentFunction.getProgram());
					arm = null;
					//step = false;
					Msg.showInfo(getClass(), null, "Finished", "Program Emulation Finished");
				}
				else {
					Msg.showInfo(getClass(), null, "Start", "Please setup current function to run");
				}
			}
		};
		
		action.setToolBarData(new ToolBarData(Icons.RIGHT_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
		
		action = new DockingAction("Emulate Current Function", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				emulator.setText("");
				clearStack();
				currentFunction = functionManager.getFunctionContaining(currentAddress);
				Address lastAddress = currentAddress.add(4);
				if(currentFunction != null) {
					while(currentFunction.equals(functionManager.getFunctionContaining(lastAddress.add(4)))) {
						lastAddress = lastAddress.add(4);
					}
					currentAddress = currentFunction.getEntryPoint();
					functionLen = lastAddress.subtract(currentAddress);
					api = new FlatProgramAPI(currentFunction.getProgram());
					byte[] code;
					try {
						code = api.getBytes(currentAddress, (int) functionLen);
						arm = new ARM_emulator(provider, Integer.parseInt(currentAddress.toString(), 16), code, api);
					} catch (MemoryAccessException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			}
		};
		action.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		action.setEnabled(true);
		dockingTool.addLocalAction(this, action);
		
		// clear current emulation
		action = new DockingAction("Clear", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				arm = null;
				//step = false;
				emulator.setText("");
				clearStack();
				labelR0.setText("0x0000");
				labelR1.setText("0x0000");
				labelR2.setText("0x0000");
				labelR3.setText("0x0000");
				labelR4.setText("0x0000");
				labelR5.setText("0x0000");
				labelR6.setText("0x0000");
				labelR7.setText("0x0000");
				labelR8.setText("0x0000");
				labelR9.setText("0x0000");
				labelR10.setText("0x0000");
				labelR11.setText("0x0000");
				labelR12.setText("0x0000");
				labelSP.setText("0x0800");
				labelLR.setText("0x0000");
				labelPC.setText("0x0000");
				labelCPSR.setText("0x0000");
				base.setText("0x10000");
			}
		};
		action.setToolBarData(new ToolBarData(Icons.DELETE_ICON, null));
		action.setEnabled(true);
		action.markHelpUnnecessary();
		dockingTool.addLocalAction(this, action);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}
	
	public long getBase() {
		return Long.parseLong(base.getText().substring(2), 16);
	}
	
	public long getBaseLen() {
		return Long.parseLong(baseLen.getText().substring(2), 16);
	}
	
	private void getMemoryContents() {
		if(arm != null) {
			memoryContents.setText("");
			long MemoryLocation = Long.parseLong(memoryLocation.getText().substring(2), 16);
			byte [] memory = arm.getMemoryAtAddress(MemoryLocation);
			memoryContents.append(String.format("%02x %02x %02x %02x", memory[0], memory[1], memory[2], memory[3]));
		}
	}
	
	private void setMemoryContents() {
		if(arm != null) {
			long MemoryLocation = Long.parseLong(memoryLocation.getText().substring(2), 16);
			try {
				byte [] MemoryContents = {(byte) Integer.parseInt(memoryContents.getText().substring(0, 2), 16), 
					(byte) Integer.parseInt(memoryContents.getText().substring(3, 5), 16),
					(byte) Integer.parseInt(memoryContents.getText().substring(6, 8), 16),
					(byte) Integer.parseInt(memoryContents.getText().substring(9, 11), 16)};
				arm.setMemoryAtAddress(MemoryLocation, MemoryContents);
			}catch (NumberFormatException e) {
				Msg.showInfo(getClass(), null, "OPPS", String.format("Please format new instruction as: 01 02 03 04\n %s", e));
			} catch (StringIndexOutOfBoundsException e) {
				Msg.showInfo(getClass(), null, "OPPS", String.format("Please format new instruction as: 01 02 03 04\n %s", e));
			}
		}
	}
	
	private void updateMemory() {
		if(arm != null) {
			memoryView.setText("");
			long currentMemoryLocation = arm.getBase();
			int location = 0;
			byte [] memory = arm.getMemory();
			while(currentMemoryLocation < memory.length) {
				memoryView.append(String.format("0x%08x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x %02x%02x\n", currentMemoryLocation, 
						memory[location], memory[location + 1], memory[location + 2], memory[location + 3],
						memory[location + 4], memory[location + 5], memory[location + 6], memory[location + 7],
						memory[location + 8], memory[location + 9], memory[location + 10], memory[location + 11],
						memory[location + 12], memory[location + 13], memory[location + 14], memory[location + 15]));
				location = location + 16;
				currentMemoryLocation = currentMemoryLocation + 16;
			}
		}
	}
	
	private void setCurrentAddress(Address addr, Program pg) {
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(addr, pg);
	}
	
	public void setLocation(ProgramLocation location, Program program) {
		currentAddress = location.getAddress();
		functionManager = program.getFunctionManager();
	}
}
