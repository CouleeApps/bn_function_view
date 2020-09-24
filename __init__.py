from time import sleep

from PySide2.QtCore import Qt
from PySide2.QtGui import QWindow
from PySide2.QtWidgets import QDialog, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QFormLayout, QLabel, QLineEdit, \
    QScrollArea, QComboBox, QCheckBox, QListWidget, QAbstractItemView
from binaryninja import PluginCommand, BinaryView, Function, QualifiedName, execute_on_main_thread_and_wait, \
    worker_enqueue, execute_on_main_thread, BackgroundTaskThread
from binaryninjaui.binaryninjaui import ViewFrame, UIContext, askForNewType


class FunctionEditDialog(QDialog):
    """
    Fields to display:
    analysis_skip_override            Override for skipping of automatic analysis
    analysis_skip_reason              Function analysis skip reason
    arch (read-only)                  Function architecture
    auto (read-only)                  Whether function was automatically discovered
    calling_convention                Calling convention used by the function
    can_return                        Whether function can return
    clobbered_regs                    Registers that are modified by this function
    function_type                     Function type object, can be set with either a string representing the function prototype (str(function) shows examples) or a Type object
    global_pointer_value (read-only)  Discovered value of the global pointer register, if the function uses one
    has_variable_arguments            Whether the function takes a variable number of arguments
    indirect_branches (read-only)     List of indirect branches
    name                              Symbol name for the function
    needs_update (read-only)          Whether the function has analysis that needs to be updated
    parameter_vars                    List of variables for the incoming function parameters
    platform (read-only)              Function platform
    reg_stack_adjustments             Number of entries removed from each register stack after return
    return_regs                       Registers that are used for the return value
    return_type                       Return type of the function
    session_data                      Dictionary object where plugins can store arbitrary data associated with the function
    stack_adjustment                  Number of bytes removed from the stack after return
    stack_layout (read-only)          List of function stack variables
    start (read-only)                 Function start address
    symbol (read-only)                Function symbol
    vars (read-only)                  List of function variables
    """
    VARS = [
        {"name": "name",                   "display": "Name",                       "func": lambda self: self.create_editor_name()},
        {"name": "arch",                   "display": "Architecture",               "func": lambda self: self.create_editor_arch()},
        {"name": "platform",               "display": "Platform",                   "func": lambda self: self.create_editor_platform()},
        {"name": "auto",                   "display": "Auto defined",               "func": lambda self: self.create_editor_auto()},

        {"name": "function_type",          "display": "Type",                       "func": lambda self: self.create_editor_function_type()},
        {"name": "return_type",            "display": "Return Type",                "func": lambda self: self.create_editor_return_type()},
        {"name": "calling_convention",     "display": "Calling Convention",         "func": lambda self: self.create_editor_calling_convention()},
        {"name": "has_variable_arguments", "display": "Has Variable Arguments",     "func": lambda self: self.create_editor_has_variable_arguments()},
        {"name": "can_return",             "display": "Can Return",                 "func": lambda self: self.create_editor_can_return()},

        {"name": "reg_stack_adjustments",  "display": "Register Stack Adjustments", "func": lambda self: self.create_editor_reg_stack_adjustments()},
        {"name": "stack_adjustment",       "display": "Stack Adjustment",           "func": lambda self: self.create_editor_stack_adjustment()},

        {"name": "parameter_vars",         "display": "Parameter Variables",        "func": lambda self: self.create_editor_parameter_vars()},
        {"name": "return_regs",            "display": "Return Registers",           "func": lambda self: self.create_editor_return_regs()},
        {"name": "clobbered_regs",         "display": "Clobbered Registers",        "func": lambda self: self.create_editor_clobbered_regs()},
        {"name": "stack_layout",           "display": "Stack Layout",               "func": lambda self: self.create_editor_stack_layout()},
        {"name": "vars",                   "display": "Variables",                  "func": lambda self: self.create_editor_vars()},

        {"name": "analysis_skip_override", "display": "Analysis Skip Override",     "func": lambda self: self.create_editor_analysis_skip_override()},
        {"name": "analysis_skip_reason",   "display": "Analysis Skip Reason",       "func": lambda self: self.create_editor_analysis_skip_reason()},
        {"name": "global_pointer_value",   "display": "Global Pointer Value",       "func": lambda self: self.create_editor_global_pointer_value()},
        {"name": "session_data",           "display": "Session Data",               "func": lambda self: self.create_editor_session_data()},
    ]

    def __init__(self, parent: QWidget, frame: ViewFrame, data: BinaryView, function: Function):
        QDialog.__init__(self, parent)
        self.data = data
        self.frame = frame
        self.function = function

        self.dirty = False
        self.unapplied = {}

        # Window Properties
        self.setWindowTitle(f"Edit Function {function.name} @ {function.start:x}")
        self.setMinimumSize(UIContext.getScaledWindowSize(640, 480))
        self.setAttribute(Qt.WA_DeleteOnClose)

        # Layout
        self.form = None
        layout = QVBoxLayout(self)
        scroll = QScrollArea(self)
        scroll.setWidget(self.create_editor_body())
        layout.addWidget(scroll)

        # Bottom buttons
        button_layout = QHBoxLayout()
        button_layout.setContentsMargins(0, 0, 0, 0)
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.clicked.connect(lambda: self.reject())
        self.cancel_button.setAutoDefault(False)
        button_layout.addWidget(self.cancel_button)
        button_layout.addStretch(1)
        self.apply_button = QPushButton("Apply")
        self.apply_button.clicked.connect(lambda: self.apply())
        self.apply_button.setAutoDefault(False)
        button_layout.addWidget(self.apply_button)
        self.ok_button = QPushButton("Ok")
        self.ok_button.clicked.connect(lambda: self.ok())
        self.ok_button.setDefault(True)
        button_layout.addWidget(self.ok_button)
        layout.addLayout(button_layout)

    def create_editor_body(self):
        main_panel = QWidget(self)
        self.form = QFormLayout(self)
        self.form.setFieldGrowthPolicy(QFormLayout.ExpandingFieldsGrow)
        self.form.setContentsMargins(0, 0, 0, 0)
        self.form.setAlignment(Qt.AlignJustify | Qt.AlignTop)
        main_panel.setLayout(self.form)
        self.load_editors()
        return main_panel

    def load_editors(self):
        for var in FunctionEditDialog.VARS:
            editor = None
            if "func" in var:
                editor = var["func"](self)
            if editor is None:
                editor = QLabel(str(getattr(self.function, var["name"])))
            self.form.addRow(var["display"], editor)

    def queue_apply(self, field, func):
        self.unapplied[field] = func
        self.dirty = True

        for i, var in enumerate(FunctionEditDialog.VARS):
            if var["name"] == field:
                label = self.form.itemAt(i, QFormLayout.LabelRole).widget()
                if not label.text().endswith("*"):
                    label.setText(label.text() + "*")

    def apply(self, update=True):
        self.cancel_button.setDisabled(True)
        self.apply_button.setDisabled(True)
        self.ok_button.setDisabled(True)

        self.data.begin_undo_actions()
        for func in self.unapplied.values():
            func()
        self.unapplied = {}
        self.dirty = False
        self.data.commit_undo_actions()

        class UpdateTask(BackgroundTaskThread):
            def __init__(self, ui):
                BackgroundTaskThread.__init__(self, "", False)
                self.ui = ui

            def run(self):
                def finish():
                    # Clear form
                    while self.ui.form.rowCount() > 0:
                        self.ui.form.removeRow(0)
                    self.ui.load_editors()

                    self.ui.cancel_button.setDisabled(False)
                    self.ui.apply_button.setDisabled(False)
                    self.ui.ok_button.setDisabled(False)

                sleep(1)
                execute_on_main_thread(finish)

        if update:
            UpdateTask(self).start()

    def ok(self):
        self.apply(False)
        self.accept()

    def create_text_editor(self, attr, apply_fn):
        def setter(text):
            self.queue_apply(attr, lambda: apply_fn(text))

        editor = QLineEdit(self)
        editor.setText(str(getattr(self.function, attr)))
        editor.textChanged.connect(lambda text: setter(text))
        return editor

    def create_bool_editor(self, attr, apply_fn):
        def setter(state):
            self.queue_apply(attr, lambda: apply_fn(state == Qt.Checked))

        editor = QCheckBox(self)
        editor.setChecked(bool(getattr(self.function, attr)))
        editor.stateChanged.connect(lambda state: setter(state))
        return editor

    # Name field

    def create_editor_name(self):
        return self.create_text_editor("name", self.apply_name)

    def apply_name(self, name):
        self.function.name = name
        self.setWindowTitle(f"Edit Function {self.function.name} @ {self.function.start:x}")

    # arch field

    def create_editor_arch(self):
        return QLabel(f"{self.function.arch.name}")

    # platform field

    def create_editor_platform(self):
        return QLabel(f"{self.function.platform.name}")

    # auto field

    def create_editor_auto(self):
        return QLabel(f"{self.function.auto}")

    # function_type field

    def create_editor_function_type(self):
        return self.create_text_editor("function_type", self.apply_function_type)

    def apply_function_type(self, function_type):
        parse = self.data.parse_type_string(function_type)
        if parse is not None:
            new_type, name = parse
            self.function.function_type = new_type

    # return_type field

    def create_editor_return_type(self):
        return self.create_text_editor("return_type", self.apply_return_type)

    def apply_return_type(self, return_type):
        parse = self.data.parse_type_string(return_type)
        if parse is not None:
            new_type, name = parse
            self.function.return_type = new_type

    # calling_convention field

    def create_editor_calling_convention(self):
        editor = QComboBox(self)
        conventions = list(self.data.arch.calling_conventions.items())
        current_value = self.function.calling_convention
        current_index = 0
        for i, (name, convention) in enumerate(conventions):
            if current_value.name == convention.name:
                current_index = i
            editor.addItem(convention.name, convention.name)

        def setter(index):
            self.set_calling_convention(conventions[index][1])

        editor.setCurrentIndex(current_index)
        editor.currentIndexChanged.connect(setter)

        return editor

    def set_calling_convention(self, calling_convention):
        self.queue_apply("calling_convention", lambda: self.apply_calling_convention(calling_convention))

    def apply_calling_convention(self, calling_convention):
        self.function.calling_convention = calling_convention

    # has_variable_arguments field

    def create_editor_has_variable_arguments(self):
        return self.create_bool_editor("has_variable_arguments", self.apply_has_variable_arguments)

    def apply_has_variable_arguments(self, has_variable_arguments):
        self.function.has_variable_arguments = has_variable_arguments

    # can_return field

    def create_editor_can_return(self):
        return self.create_bool_editor("can_return", self.apply_can_return)

    def apply_can_return(self, can_return):
        self.function.can_return = can_return

    # reg_stack_adjustments field

    def create_editor_reg_stack_adjustments(self):
        return None

    def set_reg_stack_adjustments(self, reg_stack_adjustments):
        self.queue_apply("reg_stack_adjustments", lambda: self.apply_reg_stack_adjustments(reg_stack_adjustments))

    def apply_reg_stack_adjustments(self, reg_stack_adjustments):
        pass

    # stack_adjustment field

    def create_editor_stack_adjustment(self):
        return None

    def set_stack_adjustment(self, stack_adjustment):
        self.queue_apply("stack_adjustment", lambda: self.apply_stack_adjustment(stack_adjustment))

    def apply_stack_adjustment(self, stack_adjustment):
        pass

    # parameter_vars field

    def create_editor_parameter_vars(self):
        return None

    def set_parameter_vars(self, parameter_vars):
        self.queue_apply("parameter_vars", lambda: self.apply_parameter_vars(parameter_vars))

    def apply_parameter_vars(self, parameter_vars):
        pass

    # return_regs field

    def create_editor_return_regs(self):
        editor = QListWidget(self)
        editor.setSelectionMode(QAbstractItemView.MultiSelection)
        for name, reg in self.data.arch.regs.items():
            editor.addItem(name)
            item = editor.item(editor.count() - 1)
            if name in self.function.return_regs:
                item.setSelected(True)

        def get_selection():
            selection = []
            for i in range(editor.count()):
                if editor.item(i).isSelected():
                    selection.append(editor.item(i).text())
            return selection

        editor.clicked.connect(lambda: self.set_return_regs(get_selection()))
        return editor

    def set_return_regs(self, return_regs):
        self.queue_apply("return_regs", lambda: self.apply_return_regs(return_regs))

    def apply_return_regs(self, return_regs):
        self.function.return_regs = return_regs

    # clobbered_regs field

    def create_editor_clobbered_regs(self):
        editor = QListWidget(self)
        editor.setSelectionMode(QAbstractItemView.MultiSelection)
        for name, reg in self.data.arch.regs.items():
            editor.addItem(name)
            item = editor.item(editor.count() - 1)
            if name in self.function.clobbered_regs:
                item.setSelected(True)

        def get_selection():
            selection = []
            for i in range(editor.count()):
                if editor.item(i).isSelected():
                    selection.append(editor.item(i).text())
            return selection

        editor.clicked.connect(lambda: self.set_clobbered_regs(get_selection()))
        return editor

    def set_clobbered_regs(self, clobbered_regs):
        self.queue_apply("clobbered_regs", lambda: self.apply_clobbered_regs(clobbered_regs))

    def apply_clobbered_regs(self, clobbered_regs):
        self.function.clobbered_regs = clobbered_regs

    # stack_layout field

    def create_editor_stack_layout(self):
        return None

    def set_stack_layout(self, stack_layout):
        self.queue_apply("stack_layout", lambda: self.apply_stack_layout(stack_layout))

    def apply_stack_layout(self, stack_layout):
        pass

    # vars field

    def create_editor_vars(self):
        return None

    def set_vars(self, vars):
        self.queue_apply("vars", lambda: self.apply_vars(vars))

    def apply_vars(self, vars):
        pass

    # analysis_skip_override field

    def create_editor_analysis_skip_override(self):
        return None

    def set_analysis_skip_override(self, analysis_skip_override):
        self.queue_apply("analysis_skip_override", lambda: self.apply_analysis_skip_override(analysis_skip_override))

    def apply_analysis_skip_override(self, analysis_skip_override):
        pass

    # analysis_skip_reason field

    def create_editor_analysis_skip_reason(self):
        return None

    def set_analysis_skip_reason(self, analysis_skip_reason):
        self.queue_apply("analysis_skip_reason", lambda: self.apply_analysis_skip_reason(analysis_skip_reason))

    def apply_analysis_skip_reason(self, analysis_skip_reason):
        pass

    # global_pointer_value field

    def create_editor_global_pointer_value(self):
        return None

    def set_global_pointer_value(self, global_pointer_value):
        self.queue_apply("global_pointer_value", lambda: self.apply_global_pointer_value(global_pointer_value))

    def apply_global_pointer_value(self, global_pointer_value):
        pass

    # session_data field

    def create_editor_session_data(self):
        return None

    def set_session_data(self, session_data):
        self.queue_apply("session_data", lambda: self.apply_session_data(session_data))

    def apply_session_data(self, session_data):
        pass


def edit_function_type(bv: BinaryView, func: Function):
    # PySide "helpfully" cleans these up unless we save them
    context = UIContext.activeContext()
    main_window = context.mainWindow()
    dialog = FunctionEditDialog(main_window, ViewFrame.viewFrameForWidget(main_window), bv, func)
    dialog.show()


PluginCommand.register_for_function("Edit Function Type...", "Edit function type...", edit_function_type)


try:
	import pydevd_pycharm
	pydevd_pycharm.settrace('localhost', port=33333, stdoutToServer=True, stderrToServer=True, suspend=False)
except:
	pass
