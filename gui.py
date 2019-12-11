import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
#tk.messagebox, tk.filedialog 이렇게 사용할 경우 import error 발생. 직접 messagebox, filedialog를 import해서 사용해야 된다.

class MyFrame(tk.Frame):
    #Open file 버튼 클릭 시 실행, 파일 경로 및 내용 가져옴
    def openPattern(self):
        if self.state == 0:
            messagebox.showwarning("메시지 상자", "라디오버튼을 선택해주세요.")
            return False
        path = filedialog.askopenfilename()
        if not path:
            return False

        self.f4Text.configure(state='normal')
        self.f4Text2.configure(state='normal')

        ext = path.split(".")[-1]
        # readFile 함수에서 파일 읽기 성공(True), 읽은 파일 내용, 읽은 키 내용 리턴 -> state에 따라 다르게 처리
        if self.state == 1:
            if ext != "txt":
                messagebox.showwarning("메시지 상자", "txt 파일만 가능합니다.")
                return False
            result, filetxt, encKeys = self.readFile(path, self.state)
            if result:
                self.f4Text.delete(1.0, tk.END)
                self.f4Text.insert(1.0, filetxt)
            else:
                messagebox.showerror("메시지 상자", "파일을 읽는데 실패하였습니다.")
                return False
        elif self.state == 2:
            if ext != "enc":
                messagebox.showwarning("메시지 상자", "enc 파일만 가능합니다.")
                return False
            result, filetxt, encKeys = self.readFile(path, self.state)
            if result:
                self.f4Text.delete(1.0, tk.END)
                self.f4Text2.delete(1.0, tk.END)
                self.f4Text.insert(1.0, filetxt)
                self.f4Text2.insert(1.0, encKeys)
                self.f4Text2.configure(state='disabled')
            else:
                messagebox.showerror("메시지 상자", "파일을 읽는데 실패하였습니다.")
                return False

        self.f2Label2.config(text=path)
        self.f4Text.configure(state='disabled')

    # 암호화 함수 - 파라메터는 파일이름, 암호화 할 파일본문, 비밀번호 합
    def encryption(self, filename, txt, pwcode):
        # 텍스트로부터 고유 글자 뽑아내서 랜덤 번호 암호키 만들기
        import random
        str_to_encode = set(list(txt))
        codeDict = dict(zip(str_to_encode, random.sample(range(len(str_to_encode)), len(str_to_encode))))

        # 텍스트 암호화
        codedText = ''
        for t in txt:
            codedText += str(codeDict[t]) + ' '

        # 암호화된 텍스트 저장
        filename = filename.split('.')[0]  # 확장자를 제외하고 따로 저장
        outf1 = open(filename + '.enc', 'w', encoding='utf-8')
        outf1.write(codedText)
        outf1.close()

        # 비밀번호 합을 이용하여 암호키 암호화
        encKeys = ''
        for c in codeDict.items():
            encKeys += str(ord(c[0]) + pwcode) + ' '
            encKeys += str(c[1] + pwcode) + ' '

        # 암호화된 암호키 저장
        outf2 = open(filename + '.key', 'w')
        outf2.write(encKeys)
        outf2.close()

        # 암호키 딕셔너리, 암호화 된 텍스트, 암호화된 암호키를 리턴
        return codeDict, codedText, encKeys

    # 복호화 함수 - 파라메터는 파일이름, 암호화 된 파일본문, 비밀번호 합, 암호키(암호화된 상태)
    def decryption(self, filename, txt, pwcode, enkeys):
        enkeys = enkeys.split()  # 암호화된 암호키 텍스트를 공백을 이용해 리스트로 분리
        codeDict = {}  # 복호키 저장할 dictionary
        decodedText = ''
        try:
            # 암호화된 암호키를 비밀번호합을 이용해 복호키로 복호화
            for i in range(0, len(enkeys), 2):
                codeDict[int(enkeys[i + 1]) - pwcode] = chr(int(enkeys[i]) - pwcode)

            #raise Exception

            # 암호화된 텍스트를 복호키를 이용해 복호화
            for t in txt.split():
                decodedText += codeDict[int(t)]
        except:
            # 복호화 실패하면 False를 리턴
            return False, codeDict, decodedText

        # 복호화 된 텍스트 저장
        filename = filename.split('.')[0]  # 확장자를 제외하고 따로 저장
        outf = open(filename + '.dec', 'w', encoding='utf-8')
        outf.write(decodedText)
        outf.close()

        # 복호키 딕셔너리, 복호화 된 텍스트 리턴
        return True, codeDict, decodedText

    # 파일 읽기 함수 - 파라메터는 파일경로, 암호화(1)인지 복호화(2)인지 여부
    def readFile(self, filepath, choice):
        try:
            # 대상 파일 열기
            inf = open(filepath, encoding='utf-8')
            filetxt = inf.read(self.limit)
            inf.close()

            #raise IOError

            # 복호화의 경우, 키 파일 열기
            encKeys = []
            if choice == 2:  # Decryption
                inf = open(filepath.split('.')[0] + '.key')
                encKeys = inf.read()
                inf.close()

            # 파일 읽기 성공(True), 읽은 파일 내용, 읽은 키 내용 리턴
            return True, filetxt, encKeys

        except IOError as err:
            # 파일 읽기 실패하면 파일 읽기 실패(False)와 실패 사유 메시지 리턴
            return False, 'I/O Error {}'.format(err), "error"

    # 비밀번호 형식 체크 함수
    def checkPW(self, pw):
        pwcode = False
        # 비밀번호 자리 수 확인
        if len(pw) != 4:
            # 자리 수 안 맞으면 False 리턴
            return False
        # 비밀번호 합을 구하면서 중간에 공백이 있는지 여부도 같이 확인
        else:
            for p in pw:
                pwcode += ord(p)  # 유니코드로 바꿔서 합을 구함
                if p.isspace():
                    # 하나라도 공백이 있으면 False 리턴
                    return False
            # 비밀번호 형식이 잘 맞으면 4자리 합을 리턴
            return pwcode

    # 라디오 버튼 클릭 시 초기화 및 상태 설정
    def selectState(self):
        self.f4Text.configure(state='normal')
        self.f4Text2.configure(state='normal')
        self.f4Text3.configure(state='normal')
        self.f4Text4.configure(state='normal')
        self.f2Label2.config(text='')
        self.f3Entry.delete(0, tk.END)
        self.f4Text.delete(1.0, tk.END)
        self.f4Text2.delete(1.0, tk.END)
        self.f4Text3.delete(1.0, tk.END)
        self.f4Text4.delete(1.0, tk.END)
        if self.f1Var.get() == 1:
            self.state = 1
        elif self.f1Var.get() == 2:
            self.state = 2

    # 암호화, 복호화하는 RUN 버튼 클릭 시 실행, 암호화 복호화된 파일 생성 및 내용을 보여줌
    def runResult(self):
        pw = self.f3Entry.get()
        password = self.checkPW(pw)

        filePath = self.f2Label2.cget("text")
        fileContent = self.f4Text.get("1.0", tk.END)
        fileKeyContent = self.f4Text2.get("1.0", tk.END)

        if self.state == 0:
            messagebox.showwarning("메시지 상자", "라디오버튼을 선택해주세요.")
            return False

        if not filePath:
            messagebox.showwarning("메시지 상자", "파일을 선택해주세요")
            return False

        if not password:
            messagebox.showwarning("메시지 상자", "올바른 비밀번호를 입력해주세요.")
            return False

        self.f4Text3.delete(1.0, tk.END)
        self.f4Text4.delete(1.0, tk.END)

        if self.state == 1:
            # 암호키 딕셔너리, 암호화 된 텍스트, 암호화된 암호키를 리턴
            codeDict, codedText, encKeys = self.encryption(filePath, fileContent, password)
            self.f4Text2.delete(1.0, tk.END)
            self.f4Text2.insert(1.0, codeDict)
            self.f4Text3.insert(1.0, codedText)
            self.f4Text4.insert(1.0, encKeys)
        elif self.state == 2:
            # 복호키 딕셔너리, 복호화 된 텍스트 리턴
            result, codeDict, decodedText = self.decryption(filePath, fileContent, password, fileKeyContent)
            if result:
                self.f4Text3.insert(1.0, codeDict)
                self.f4Text4.insert(1.0, decodedText)
            else:
                messagebox.showwarning("메시지 상자", "잘못된 비밀번호입니다.")

    # 프로그램 초기화, 자리 배치 및 함수 연결
    def __init__(self, master):
        tk.Frame.__init__(self, master)

        self.master = master
        self.master.title("Encryption/Decryption")
        self.pack(fill=tk.BOTH, expand=True)

        self.state = 0
        self.limit = 500

        #영역1
        frame1 = tk.Frame(self)
        frame1.pack(fill=tk.X)

        f1Label = tk.Label(frame1, text="Choose 1 or 2", width=20)
        f1Label.pack(side=tk.LEFT, padx=10, pady=10,)

        self.f1Var = tk.IntVar()

        f1Radio1 = tk.Radiobutton(frame1, text="1-Encryption", variable=self.f1Var,  value=1, command=self.selectState)
        f1Radio1.pack(side=tk.LEFT, padx=10, pady=10,)

        f1Radio2 = tk.Radiobutton(frame1, text="1-Decryption", variable=self.f1Var,  value=2, command=self.selectState)
        f1Radio2.pack(side=tk.LEFT, padx=10, pady=10,)

        #영역2
        frame2 = tk.Frame(self)
        frame2.pack(fill=tk.X)

        f2Label = tk.Label(frame2, text="file name", width=20)
        f2Label.pack(side=tk.LEFT, padx=10, pady=10,)

        self.f2Label2 = tk.Label(frame2, text="", width=40)
        self.f2Label2.pack(side=tk.LEFT, padx=10, pady=10,)

        f2Button = tk.Button(frame2, width=15, text="Open File", command=self.openPattern)
        f2Button.pack(side=tk.RIGHT, padx=10, pady=10,)

        #영역3
        frame3 = tk.Frame(self)
        frame3.pack(fill=tk.X)

        f3Label = tk.Label(frame3, text="password(4 characters)", width=20)
        f3Label.pack(side=tk.LEFT, padx=10, pady=10,)

        self.f3Entry = tk.Entry(frame3, show="*")
        self.f3Entry.pack(side=tk.LEFT, padx=10, pady=10)

        f3Button = tk.Button(frame3, width=15, text="RUN", command=self.runResult)
        f3Button.pack(side=tk.RIGHT, padx=10, pady=10,)

        #영역4
        frame4 = tk.Frame(self)
        frame4.pack(fill=tk.BOTH, expand=True)

        self.f4Text = tk.Text(frame4, height=7)
        self.f4Text.pack(fill=tk.X, pady=1, padx=20)

        self.f4Text2 = tk.Text(frame4, height=7)
        self.f4Text2.pack(fill=tk.X, pady=1, padx=20)

        self.f4Text3 = tk.Text(frame4, height=7)
        self.f4Text3.pack(fill=tk.X, pady=1, padx=20)

        self.f4Text4 = tk.Text(frame4, height=7)
        self.f4Text4.pack(fill=tk.X, pady=1, padx=20)

#프로그램 실행
def main():
    root = tk.Tk()
    root.geometry("700x550+100+100")
    app = MyFrame(root)
    root.mainloop()


if __name__ == '__main__':
    main()