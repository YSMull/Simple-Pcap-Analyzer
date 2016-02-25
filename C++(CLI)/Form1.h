#pragma once
#include "算法一.h"
#include <msclr\marshal_cppstd.h>

using namespace msclr::interop;
namespace 信息安全C {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::IO;
	using namespace System::Threading;
	using namespace System::Security::Cryptography;
	using namespace System::Text;
	using namespace System::Globalization;


	/// <summary>
	/// Form1 摘要
	/// </summary>
	
	public ref class Form1 : public System::Windows::Forms::Form
	{
	public:
		Form1(void)
		{
			InitializeComponent();
			//
			//TODO: 在此处添加构造函数代码
			//

			
			
		}

	protected:
		/// <summary>
		/// 清理所有正在使用的资源。
		/// </summary>
		~Form1()
		{
			if (components)
			{
				delete components;
			}
		}
	public:	void suanfa1()
	{	
		button5->Enabled = false;
		string pcap_file = marshal_as<std::string>(textBox1->Text);
		string out_dir = marshal_as<std::string>(textBox2->Text);
		DirectoryInfo^ dir = gcnew DirectoryInfo(textBox2->Text + "\\result");
		ifstream in;
		
		if(_access((out_dir + "\\result").c_str(), 0) == 0)//存在result文件夹
			//system("RD /s/q result");//删除当前目录的result文件夹
			dir->Delete(true);
		_mkdir((out_dir + "\\result").c_str());
		_mkdir((out_dir + "\\result\\tcp").c_str());
		_mkdir((out_dir + "\\result\\udp").c_str());

		
		clock_t t_start, t_end;
		t_start = clock();

		in.open(pcap_file, ios::in | ios::binary);
		if(!in.is_open()) {
			richTextBox1->AppendText ( marshal_as<System::String^>("无法打开 “" + pcap_file + "” ,请确认文件名输入是否正确!") );
			button5->Enabled = true;
			return;
		}
		
		richTextBox1->AppendText("*******************算法一*******************\n");
		richTextBox1->AppendText("正在解析pcap文件......\n");
		pcap_file_header pfh;
		in.read((char*)&pfh, sizeof(pfh));
		vector<package> package_list;
		//long h = 1;
		//long k = 0;

		while(!in.eof()) {
			package pg;
			pcap_header ph;
			if(in.read((char*)&ph, sizeof(ph)).gcount() == 0) break;

			pg.ph = ph;
			const uint32_t total_len = static_cast<uint32_t>(sizeof(int32_t) + ph.capture_len);
			pg.pd = static_cast<pcap_data*>(::malloc(total_len));
			pg.pd->len = ph.capture_len;
			in.read(pg.pd->data, ph.capture_len);
			package_list.push_back(pg);
		}
		in.close();
		richTextBox1->AppendText( "解析完毕\n");
		richTextBox1->AppendText("正在分组会话......");
		map<five, vector<package> > package_group;
		for(size_t i = 0; i < package_list.size(); i++) {
			five f;
			f.protcol = package_list[i].pd->data[23];
			memcpy(&f.ip1, &package_list[i].pd->data[26], 4);
			memcpy(&f.ip2, &package_list[i].pd->data[30], 4);
			memcpy(&f.port1, &package_list[i].pd->data[34], 2);
			memcpy(&f.port2, &package_list[i].pd->data[36], 2);
			if((int) package_list[i].pd->data[23] == 6 ||
				(int) package_list[i].pd->data[23] == 17 ) {
					package_group[f].push_back(package_list[i]);
				}
		}

		richTextBox1->AppendText("会话分组完毕，正在生成结果...(见 result 文件夹)\n");

		ofstream report;
		report.open(out_dir + "\\result\\report.txt", ios::out);
		map<five, vector<package> >::iterator it;
		for(it = package_group.begin(); it != package_group.end(); ++it) {
			ofstream pcap;
			string file_name;
			string protcol;
			string dir;
			ostringstream port1, port2;
			port1 << dec << swapInt16((*it).first.port1);
			port2 << dec << swapInt16((*it).first.port2);
			if((*it).first.protcol == 6) {
				protcol = "tcp";
				dir = out_dir + "\\result\\tcp\\";
			} else {
				protcol = "udp";
				dir = out_dir + "\\result\\udp\\";
			}
			uint32_t ip1, ip2;
			string port11,port21;
			if((*it).first.ip1 < (*it).first.ip2) {
				ip1 = (*it).first.ip1;
				ip2 = (*it).first.ip2;
				port11 = port1.str();
				port21 = port2.str();
			} else {
				ip1 = (*it).first.ip2;
				ip2 = (*it).first.ip1;
				port11 = port2.str();
				port21 = port1.str();
			}
			file_name = "[" + protcol + "][" + print_ip((*it).first.ip1) + "][" + port11 + "][" + print_ip((*it).first.ip2) + "][" + port21 + "].pcap";
			pcap.open(dir + file_name, ios::out | ios::binary);
			pcap.write((char*)&pfh, sizeof(pfh));
			vector<package>::iterator it2;
			for(it2 = (*it).second.begin(); it2 != (*it).second.end(); ++it2) {
				pcap.write((char*)&(*it2).ph, sizeof(pcap_header));
				pcap.write((char*)(*it2).pd->data, (*it2).pd->len);
			}
			report << "write " + file_name + " done\n";
			pcap.close();
		}
		report.close();
		t_end = clock();
		richTextBox1->AppendText( "总共耗时：" + System::Convert::ToString(double(t_end - t_start) / CLOCKS_PER_SEC) + "秒.\n");
		button5->Enabled = true;
		textBox3->Text = textBox2->Text + "\\result\\tcp";
	}
	
	public:	void suanfa2()
	{
		//textBox3->Text = "C:\\Users\\mys\\Desktop\\test";
		button6->Enabled = false;
		DirectoryInfo^ di = gcnew DirectoryInfo(textBox3->Text);
		//di->GetDirectories();//获取子文件夹列表

		clock_t t_start, t_end;
		t_start = clock();
		richTextBox1->AppendText("\n*******************算法二*******************\n");
		richTextBox1->AppendText("正在解析pcap文件......\n");
		
		array<FileInfo^>^ files = di->GetFiles();//获取文件列表
		
		
		for each (FileInfo^ file in files)
		{
			if (!file->Name->EndsWith(".pcap")) {
				continue;
			}
			ifstream in;
			string pcap_file = marshal_as<std::string>(di->FullName + "\\" + file->Name);
			in.open(pcap_file, ios::in | ios::binary);
			if (!in.is_open()) {
				richTextBox1->AppendText(marshal_as<System::String^>
					("无法打开 “" + pcap_file + " ”!"));
				continue;
			}
			//richTextBox1->AppendText(di->FullName + "\\" + file->Name + "\n");
			pcap_file_header pfh;
			in.read((char*)&pfh, sizeof(pfh));
			vector<package> package_list;
			while (!in.eof()) {
				package pg;
				pcap_header ph;
				if (in.read((char*)&ph, sizeof(ph)).gcount() == 0) break;

				pg.ph = ph;
				const uint32_t total_len = 
					static_cast<uint32_t>(sizeof(int32_t)+ph.capture_len);
				pg.pd = static_cast<pcap_data*>(::malloc(total_len));
				pg.pd->len = ph.capture_len;
				in.read(pg.pd->data, ph.capture_len);
				package_list.push_back(pg);
			}
			in.close();

			ofstream out;
			out.open(pcap_file + ".txt", ios::out | ios::binary);
			uint32_t cur_src_ip = 0;
			
			for (size_t i = 0; i < package_list.size(); i++) {
				unsigned short total_length;//bytes
				unsigned char  tcp_length;//bits
				uint32_t last_ip = cur_src_ip;
				memcpy(&total_length, &package_list[i].pd->data[16], 2);
				memcpy(&tcp_length, &package_list[i].pd->data[46], 1);
				memcpy(&cur_src_ip, &package_list[i].pd->data[26], 4);
				
				if (last_ip != cur_src_ip) {
					out.write("\n", 1);
				}
				int data_length = swapInt16(total_length) - 20 - tcp_length / 4;
				char *data;
				if (data_length > 0) {
					data = static_cast<char*>(::malloc(data_length));
					memcpy(
						data, 
						&package_list[i].pd->data[14 + 20 + tcp_length / 4], 
						data_length);
					out.write(data, data_length);	
				}
			}
			out.close();
		}
		t_end = clock();
		richTextBox1->AppendText("总共耗时：" + System::Convert::ToString(double(t_end - t_start) / CLOCKS_PER_SEC) + "秒.\n");
		button6->Enabled = true;
	}

	public: String^ GenerateKey()
	{
		DESCryptoServiceProvider^ desCrypto = (DESCryptoServiceProvider^)DESCryptoServiceProvider::Create();
		return ASCIIEncoding::ASCII->GetString(desCrypto->Key);
	}
	// 加密字符串   
	public: String^ EncryptString(String^ sInputString, String^ sKey)
	{
		array<System::Byte>^ data = Encoding::UTF8->GetBytes(sInputString);

		DESCryptoServiceProvider^ DESa = gcnew DESCryptoServiceProvider();
		DESa->Key = ASCIIEncoding::ASCII->GetBytes(sKey);
		DESa->IV = ASCIIEncoding::ASCII->GetBytes(sKey);
		ICryptoTransform^ desencrypt = DESa->CreateEncryptor();
		array<System::Byte>^ result = desencrypt->TransformFinalBlock(data, 0, data->Length);
		return BitConverter::ToString(result);
	}
	// 解密字符串
	public: String^ DecryptString(String^ sInputString, String^ sKey)
	{
		//array<System::String^>^ sInput = sInputString->Split("-"->ToCharArray());
		array<System::String^>^ sInput = sInputString->Split('-');
		array<System::Byte>^ data = gcnew array<System::Byte>(sInput->Length);

		for (int i = 0; i < sInput->Length; i++)
		{
			data[i] = Byte::Parse(sInput[i], NumberStyles::HexNumber);
		}
		DESCryptoServiceProvider^ DESa = gcnew DESCryptoServiceProvider();
		DESa->Key = ASCIIEncoding::ASCII->GetBytes(sKey);
		DESa->IV = ASCIIEncoding::ASCII->GetBytes(sKey);
		ICryptoTransform^ desencrypt = DESa->CreateDecryptor();
		array<System::Byte>^ result = desencrypt->TransformFinalBlock(data, 0, data->Length);
		return Encoding::UTF8->GetString(result);
	}
	
	private: System::Windows::Forms::Button^  button1;
	protected: 
	private: System::Windows::Forms::TextBox^  textBox1;
	private: System::Windows::Forms::TextBox^  textBox2;
	private: System::Windows::Forms::Button^  button2;
	private: System::Windows::Forms::TextBox^  textBox3;
	private: System::Windows::Forms::Button^  button3;


	private: System::Windows::Forms::TableLayoutPanel^  tableLayoutPanel1;
	private: System::Windows::Forms::Button^  button5;
	private: System::Windows::Forms::Button^  button6;
	private: System::Windows::Forms::Button^  button4;

	private: System::Windows::Forms::Button^  button7;
	private: System::Windows::Forms::RichTextBox^  richTextBox1;
	private: System::Windows::Forms::Label^  label1;
	private: System::Windows::Forms::TableLayoutPanel^  tableLayoutPanel2;
	private: System::Windows::Forms::Label^  label2;
	private: System::Windows::Forms::Label^  label3;
	private: System::Windows::Forms::Label^  label4;
	private: System::Windows::Forms::Label^  label5;
	private: System::Windows::Forms::TextBox^  textBox6;
	private: System::Windows::Forms::TextBox^  textBox5;
	private: System::Windows::Forms::TextBox^  textBox4;



	private:
		/// <summary>
		/// 必需的设计器变量。
		/// </summary>
		System::ComponentModel::Container ^components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// 设计器支持所需的方法 - 不要
		/// 使用代码编辑器修改此方法的内容。
		/// </summary>
		void InitializeComponent(void)
		{
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->textBox1 = (gcnew System::Windows::Forms::TextBox());
			this->textBox2 = (gcnew System::Windows::Forms::TextBox());
			this->button2 = (gcnew System::Windows::Forms::Button());
			this->textBox3 = (gcnew System::Windows::Forms::TextBox());
			this->button3 = (gcnew System::Windows::Forms::Button());
			this->tableLayoutPanel1 = (gcnew System::Windows::Forms::TableLayoutPanel());
			this->button5 = (gcnew System::Windows::Forms::Button());
			this->button6 = (gcnew System::Windows::Forms::Button());
			this->button7 = (gcnew System::Windows::Forms::Button());
			this->richTextBox1 = (gcnew System::Windows::Forms::RichTextBox());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->button4 = (gcnew System::Windows::Forms::Button());
			this->tableLayoutPanel2 = (gcnew System::Windows::Forms::TableLayoutPanel());
			this->textBox6 = (gcnew System::Windows::Forms::TextBox());
			this->textBox5 = (gcnew System::Windows::Forms::TextBox());
			this->textBox4 = (gcnew System::Windows::Forms::TextBox());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->label5 = (gcnew System::Windows::Forms::Label());
			this->tableLayoutPanel1->SuspendLayout();
			this->tableLayoutPanel2->SuspendLayout();
			this->SuspendLayout();
			// 
			// button1
			// 
			this->button1->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->button1->Location = System::Drawing::Point(572, 9);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(97, 25);
			this->button1->TabIndex = 0;
			this->button1->Text = L"输入文件";
			this->button1->UseVisualStyleBackColor = true;
			this->button1->Click += gcnew System::EventHandler(this, &Form1::button1_Click);
			// 
			// textBox1
			// 
			this->textBox1->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->textBox1->Enabled = false;
			this->textBox1->Location = System::Drawing::Point(46, 9);
			this->textBox1->Multiline = true;
			this->textBox1->Name = L"textBox1";
			this->textBox1->Size = System::Drawing::Size(520, 25);
			this->textBox1->TabIndex = 1;
			this->textBox1->TextChanged += gcnew System::EventHandler(this, &Form1::textBox1_TextChanged);
			// 
			// textBox2
			// 
			this->textBox2->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->textBox2->Location = System::Drawing::Point(46, 54);
			this->textBox2->Name = L"textBox2";
			this->textBox2->Size = System::Drawing::Size(520, 25);
			this->textBox2->TabIndex = 3;
			// 
			// button2
			// 
			this->button2->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->button2->Location = System::Drawing::Point(572, 54);
			this->button2->Name = L"button2";
			this->button2->Size = System::Drawing::Size(97, 25);
			this->button2->TabIndex = 2;
			this->button2->Text = L"输出目录";
			this->button2->UseVisualStyleBackColor = true;
			this->button2->Click += gcnew System::EventHandler(this, &Form1::button2_Click);
			// 
			// textBox3
			// 
			this->textBox3->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->textBox3->Location = System::Drawing::Point(46, 99);
			this->textBox3->Name = L"textBox3";
			this->textBox3->Size = System::Drawing::Size(520, 25);
			this->textBox3->TabIndex = 5;
			// 
			// button3
			// 
			this->button3->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->button3->Location = System::Drawing::Point(572, 99);
			this->button3->Name = L"button3";
			this->button3->Size = System::Drawing::Size(97, 25);
			this->button3->TabIndex = 4;
			this->button3->Text = L"输入目录";
			this->button3->UseVisualStyleBackColor = true;
			this->button3->Click += gcnew System::EventHandler(this, &Form1::button3_Click);
			// 
			// tableLayoutPanel1
			// 
			this->tableLayoutPanel1->AutoSize = true;
			this->tableLayoutPanel1->ColumnCount = 5;
			this->tableLayoutPanel1->ColumnStyles->Add((gcnew System::Windows::Forms::ColumnStyle(System::Windows::Forms::SizeType::Percent,
				5.292793F)));
			this->tableLayoutPanel1->ColumnStyles->Add((gcnew System::Windows::Forms::ColumnStyle(System::Windows::Forms::SizeType::Percent,
				64.3018F)));
			this->tableLayoutPanel1->ColumnStyles->Add((gcnew System::Windows::Forms::ColumnStyle(System::Windows::Forms::SizeType::Percent,
				12.66374F)));
			this->tableLayoutPanel1->ColumnStyles->Add((gcnew System::Windows::Forms::ColumnStyle(System::Windows::Forms::SizeType::Percent,
				11.99014F)));
			this->tableLayoutPanel1->ColumnStyles->Add((gcnew System::Windows::Forms::ColumnStyle(System::Windows::Forms::SizeType::Percent,
				5.660378F)));
			this->tableLayoutPanel1->Controls->Add(this->button3, 2, 2);
			this->tableLayoutPanel1->Controls->Add(this->textBox2, 1, 1);
			this->tableLayoutPanel1->Controls->Add(this->button2, 2, 1);
			this->tableLayoutPanel1->Controls->Add(this->textBox3, 1, 2);
			this->tableLayoutPanel1->Controls->Add(this->textBox1, 1, 0);
			this->tableLayoutPanel1->Controls->Add(this->button1, 2, 0);
			this->tableLayoutPanel1->Controls->Add(this->button5, 3, 1);
			this->tableLayoutPanel1->Controls->Add(this->button6, 3, 2);
			this->tableLayoutPanel1->Controls->Add(this->button7, 3, 3);
			this->tableLayoutPanel1->Controls->Add(this->richTextBox1, 1, 5);
			this->tableLayoutPanel1->Controls->Add(this->label1, 1, 4);
			this->tableLayoutPanel1->Controls->Add(this->button4, 2, 3);
			this->tableLayoutPanel1->Controls->Add(this->tableLayoutPanel2, 1, 3);
			this->tableLayoutPanel1->Controls->Add(this->label5, 0, 3);
			this->tableLayoutPanel1->Dock = System::Windows::Forms::DockStyle::Fill;
			this->tableLayoutPanel1->Location = System::Drawing::Point(0, 0);
			this->tableLayoutPanel1->Name = L"tableLayoutPanel1";
			this->tableLayoutPanel1->RowCount = 6;
			this->tableLayoutPanel1->RowStyles->Add((gcnew System::Windows::Forms::RowStyle(System::Windows::Forms::SizeType::Percent, 9.821428F)));
			this->tableLayoutPanel1->RowStyles->Add((gcnew System::Windows::Forms::RowStyle(System::Windows::Forms::SizeType::Percent, 10.04464F)));
			this->tableLayoutPanel1->RowStyles->Add((gcnew System::Windows::Forms::RowStyle(System::Windows::Forms::SizeType::Percent, 10.04464F)));
			this->tableLayoutPanel1->RowStyles->Add((gcnew System::Windows::Forms::RowStyle(System::Windows::Forms::SizeType::Percent, 25.22322F)));
			this->tableLayoutPanel1->RowStyles->Add((gcnew System::Windows::Forms::RowStyle(System::Windows::Forms::SizeType::Percent, 5.133929F)));
			this->tableLayoutPanel1->RowStyles->Add((gcnew System::Windows::Forms::RowStyle(System::Windows::Forms::SizeType::Percent, 39.50893F)));
			this->tableLayoutPanel1->Size = System::Drawing::Size(818, 448);
			this->tableLayoutPanel1->TabIndex = 8;
			this->tableLayoutPanel1->Paint += gcnew System::Windows::Forms::PaintEventHandler(this, &Form1::tableLayoutPanel1_Paint);
			// 
			// button5
			// 
			this->button5->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->button5->Location = System::Drawing::Point(675, 54);
			this->button5->Name = L"button5";
			this->button5->Size = System::Drawing::Size(92, 25);
			this->button5->TabIndex = 8;
			this->button5->Text = L"算法一";
			this->button5->UseVisualStyleBackColor = true;
			this->button5->Click += gcnew System::EventHandler(this, &Form1::button5_Click);
			// 
			// button6
			// 
			this->button6->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->button6->Location = System::Drawing::Point(675, 99);
			this->button6->Name = L"button6";
			this->button6->Size = System::Drawing::Size(92, 25);
			this->button6->TabIndex = 9;
			this->button6->Text = L"算法二";
			this->button6->UseVisualStyleBackColor = true;
			this->button6->Click += gcnew System::EventHandler(this, &Form1::button6_Click);
			// 
			// button7
			// 
			this->button7->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->button7->Location = System::Drawing::Point(675, 178);
			this->button7->Name = L"button7";
			this->button7->Size = System::Drawing::Size(92, 25);
			this->button7->TabIndex = 10;
			this->button7->Text = L"解密";
			this->button7->UseVisualStyleBackColor = true;
			this->button7->Click += gcnew System::EventHandler(this, &Form1::button7_Click);
			// 
			// richTextBox1
			// 
			this->richTextBox1->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->tableLayoutPanel1->SetColumnSpan(this->richTextBox1, 3);
			this->richTextBox1->Location = System::Drawing::Point(46, 281);
			this->richTextBox1->Name = L"richTextBox1";
			this->richTextBox1->ReadOnly = true;
			this->richTextBox1->Size = System::Drawing::Size(721, 156);
			this->richTextBox1->TabIndex = 11;
			this->richTextBox1->Text = L"";
			// 
			// label1
			// 
			this->label1->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Left));
			this->label1->AutoSize = true;
			this->label1->Location = System::Drawing::Point(46, 255);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(37, 15);
			this->label1->TabIndex = 12;
			this->label1->Text = L"日志";
			// 
			// button4
			// 
			this->button4->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->button4->Location = System::Drawing::Point(572, 178);
			this->button4->Name = L"button4";
			this->button4->Size = System::Drawing::Size(97, 25);
			this->button4->TabIndex = 6;
			this->button4->Text = L"加密";
			this->button4->UseVisualStyleBackColor = true;
			this->button4->Click += gcnew System::EventHandler(this, &Form1::button4_Click);
			// 
			// tableLayoutPanel2
			// 
			this->tableLayoutPanel2->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom)
				| System::Windows::Forms::AnchorStyles::Left)
				| System::Windows::Forms::AnchorStyles::Right));
			this->tableLayoutPanel2->ColumnCount = 2;
			this->tableLayoutPanel2->ColumnStyles->Add((gcnew System::Windows::Forms::ColumnStyle(System::Windows::Forms::SizeType::Percent,
				24.42308F)));
			this->tableLayoutPanel2->ColumnStyles->Add((gcnew System::Windows::Forms::ColumnStyle(System::Windows::Forms::SizeType::Percent,
				75.57692F)));
			this->tableLayoutPanel2->Controls->Add(this->textBox6, 1, 2);
			this->tableLayoutPanel2->Controls->Add(this->textBox5, 1, 1);
			this->tableLayoutPanel2->Controls->Add(this->textBox4, 1, 0);
			this->tableLayoutPanel2->Controls->Add(this->label2, 0, 0);
			this->tableLayoutPanel2->Controls->Add(this->label3, 0, 1);
			this->tableLayoutPanel2->Controls->Add(this->label4, 0, 2);
			this->tableLayoutPanel2->Location = System::Drawing::Point(46, 137);
			this->tableLayoutPanel2->Name = L"tableLayoutPanel2";
			this->tableLayoutPanel2->RowCount = 3;
			this->tableLayoutPanel2->RowStyles->Add((gcnew System::Windows::Forms::RowStyle(System::Windows::Forms::SizeType::Percent, 33.33333F)));
			this->tableLayoutPanel2->RowStyles->Add((gcnew System::Windows::Forms::RowStyle(System::Windows::Forms::SizeType::Percent, 33.33333F)));
			this->tableLayoutPanel2->RowStyles->Add((gcnew System::Windows::Forms::RowStyle(System::Windows::Forms::SizeType::Percent, 33.33333F)));
			this->tableLayoutPanel2->Size = System::Drawing::Size(520, 107);
			this->tableLayoutPanel2->TabIndex = 13;
			// 
			// textBox6
			// 
			this->textBox6->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->textBox6->Location = System::Drawing::Point(130, 76);
			this->textBox6->Name = L"textBox6";
			this->textBox6->Size = System::Drawing::Size(387, 25);
			this->textBox6->TabIndex = 17;
			// 
			// textBox5
			// 
			this->textBox5->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->textBox5->Location = System::Drawing::Point(130, 40);
			this->textBox5->Name = L"textBox5";
			this->textBox5->Size = System::Drawing::Size(387, 25);
			this->textBox5->TabIndex = 16;
			// 
			// textBox4
			// 
			this->textBox4->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->textBox4->Location = System::Drawing::Point(130, 5);
			this->textBox4->Name = L"textBox4";
			this->textBox4->Size = System::Drawing::Size(387, 25);
			this->textBox4->TabIndex = 15;
			// 
			// label2
			// 
			this->label2->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->label2->AutoSize = true;
			this->label2->Location = System::Drawing::Point(3, 10);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(121, 15);
			this->label2->TabIndex = 0;
			this->label2->Text = L"原文";
			this->label2->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;
			// 
			// label3
			// 
			this->label3->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->label3->AutoSize = true;
			this->label3->Location = System::Drawing::Point(3, 45);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(121, 15);
			this->label3->TabIndex = 1;
			this->label3->Text = L"key";
			this->label3->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;
			// 
			// label4
			// 
			this->label4->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Left | System::Windows::Forms::AnchorStyles::Right));
			this->label4->AutoSize = true;
			this->label4->Location = System::Drawing::Point(3, 81);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(121, 15);
			this->label4->TabIndex = 2;
			this->label4->Text = L"密文";
			this->label4->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;
			// 
			// label5
			// 
			this->label5->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom));
			this->label5->AutoSize = true;
			this->label5->Font = (gcnew System::Drawing::Font(L"宋体", 9, System::Drawing::FontStyle::Bold, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(134)));
			this->label5->Location = System::Drawing::Point(4, 134);
			this->label5->Name = L"label5";
			this->label5->Size = System::Drawing::Size(34, 113);
			this->label5->TabIndex = 14;
			this->label5->Text = L"DES";
			this->label5->TextAlign = System::Drawing::ContentAlignment::MiddleCenter;
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(8, 15);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(818, 448);
			this->Controls->Add(this->tableLayoutPanel1);
			this->Name = L"Form1";
			this->Text = L"M201576111毛煜苏信息安全作业";
			this->tableLayoutPanel1->ResumeLayout(false);
			this->tableLayoutPanel1->PerformLayout();
			this->tableLayoutPanel2->ResumeLayout(false);
			this->tableLayoutPanel2->PerformLayout();
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion


private: System::Void button3_Click(System::Object^  sender, System::EventArgs^  e) {
			 FolderBrowserDialog^ save = gcnew FolderBrowserDialog;

			 if (save->ShowDialog() != System::Windows::Forms::DialogResult::OK)
			 {
				 return;
			 }
			 textBox3->Text = save->SelectedPath;
		 }
private: System::Void textBox1_TextChanged(System::Object^  sender, System::EventArgs^  e) {
		 }
private: System::Void tableLayoutPanel1_Paint(System::Object^  sender, System::Windows::Forms::PaintEventArgs^  e) {
		 }
private: System::Void button1_Click(System::Object^  sender, System::EventArgs^  e) {
			 OpenFileDialog^ open = gcnew OpenFileDialog;
			 open->Filter = "Pcap Files|*.pcap";
			 if( open->ShowDialog() != System::Windows::Forms::DialogResult::OK )
			 {
			 	return;
			 }
			 textBox1->Text = open->FileName;
			 //MessageBox::Show( open->FileName );
			 //MessageBox::Show( "OK" );
		 }
private: System::Void button2_Click(System::Object^  sender, System::EventArgs^  e) {
			 FolderBrowserDialog^ save = gcnew FolderBrowserDialog;
			 
			 if( save->ShowDialog() != System::Windows::Forms::DialogResult::OK )
			 {
			 	return;
			 }
			 textBox2->Text = save->SelectedPath;
		 }
private: System::Void button5_Click(System::Object^  sender, System::EventArgs^  e) {
			 Control::CheckForIllegalCrossThreadCalls = false;
			 Thread^ T = gcnew Thread(gcnew ThreadStart(this, &信息安全C::Form1::suanfa1));
			 T->Start();
		 }
private: System::Void listView1_SelectedIndexChanged(System::Object^  sender, System::EventArgs^  e) {

		 }
private: System::Void button6_Click(System::Object^  sender, System::EventArgs^  e) {
			 Control::CheckForIllegalCrossThreadCalls = false;
			 Thread^ T = gcnew Thread(gcnew ThreadStart(this, &信息安全C::Form1::suanfa2));
			 T->Start();
}
private: System::Void button4_Click(System::Object^  sender, System::EventArgs^  e) {
			 String^ key = textBox5->Text;
			 try
			 {
				 textBox6->Text = EncryptString(textBox4->Text, key);
			 }
			 catch (Exception^ e)
			 {
				 MessageBox::Show("key格式错误！");

			 }
}
private: System::Void button7_Click(System::Object^  sender, System::EventArgs^  e) {
			String^ key = textBox5->Text;
			try
			{
				textBox4->Text = DecryptString(textBox6->Text, key);
			}
			catch (Exception^ e)
			{
				
				MessageBox::Show("key或密文错误！");
			}
}
};


}

