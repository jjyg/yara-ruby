#    yara-ruby - Ruby bindings for the yara malware analysis library.
#    Eric Monti
#    Copyright (C) 2011 Trustwave Holdings
#
#    This program is free software: you can redistribute it and/or modify it 
#    under the terms of the GNU General Public License as published by the 
#    Free Software Foundation, either version 3 of the License, or (at your
#    option) any later version.
#
#    This program is distributed in the hope that it will be useful, but 
#    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
#    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
#    for more details.
#
#    You should have received a copy of the GNU General Public License along
#    with this program. If not, see <http://www.gnu.org/licenses/>.
#
require File.expand_path(File.dirname(__FILE__) + '/spec_helper')

describe Yara::Rules do
  it "should be a class" do
    Yara::Rules.should be_kind_of(Class)
  end

  it "should initialize cleanly" do
    lambda { Yara::Rules.new }.should_not raise_error
  end

  context "Instances" do
    before(:each) do
      @rules = Yara::Rules.new
    end

    it "should compile a file" do
      lambda { @rules.compile_file(sample_file("upx.yara")) }.should_not raise_error
    end

    it "should compile an empty file" do
      lambda { @rules.compile_file("/dev/null") }.should_not raise_error
    end


    it "should raise an error if compiling an invalid filename" do
      lambda { @rules.compile_file("so totally bogus a file") }.should raise_error
    end

    it "should raise an error if compiling a file with bad syntax" do
      lambda { @rules.compile_file(__FILE__) }.should raise_error(Yara::CompileError)
    end

    it "should raise an error if duplicate file data is compiled" do
      lambda { @rules.compile_file(sample_file("upx.yara")) }.should_not raise_error
      lambda { @rules.compile_file(sample_file("upx.yara")) }.should raise_error(Yara::CompileError)
    end

    it "should compile a string" do
      rules = File.read(sample_file("upx.yara"))
      lambda { @rules.compile_string(rules) }.should_not raise_error
    end

    it "should compile an empty string" do
      lambda { @rules.compile_string("") }.should_not raise_error
    end

    it "should raise an error if compiling a string with bad syntax" do
      rules = File.read(sample_file("upx.yara")) << "some bogus stuff\n"
      lambda { @rules.compile_string(rules) }.should raise_error(Yara::CompileError)
    end

    it "should raise an error if duplicate string data is compiled" do
      rules = File.read(sample_file("upx.yara"))
      lambda { @rules.compile_string(rules) }.should_not raise_error
      lambda { @rules.compile_string(rules) }.should raise_error(Yara::CompileError)
    end

    it "should indicate the current namespace" do
      @rules.current_namespace.should be_kind_of(String)
      @rules.current_namespace.should == "default"
    end

    it "should change the current namespace when parsing to a namespace" do
      rules = File.read(sample_file("upx.yara"))
      @rules.compile_string(rules, "yara_ns")
      @rules.current_namespace.should == "yara_ns"
    end

    it "should scan a file" do
      @rules.compile_file(sample_file("packers.yara"))
      results = @rules.scan_file(sample_file("DumpMem.exe"))
      results.should be_kind_of(Array)
      results.size.should == 1
      m = results.first
      m.should be_kind_of(Yara::Match)
      m.should be_frozen

      m.rule.should == "UPX"
      m.rule.should be_frozen

      m.namespace.should == "default"
      m.namespace.should be_frozen

      m.tags.should == ["compression", "packer", "shady"]
      m.tags.should be_frozen
      m.tags.map{|v| v.should be_frozen }

      strings = m.strings.sort
      strings.each do |ms| 
        ms.should be_kind_of(Yara::MatchString)
        ms.identifier.should be_frozen
        ms.buffer.should be_frozen
      end

      strings.map{|ms| [ms.offset, ms.identifier, md5(ms.buffer)] }.should == [
        [2824, "$noep5", "af79592a2fc536596fcbe87409734626"],
        [2830, "$noep3", "04b044f4bfeb6899b6b60ff7d6b1d103"],
        [3010, "$noep2", "8711f47b104922246e5733211cd832b1"],
        [3110, "$noep7", "71be53d1049f47219ad8f26a77255229"],
        [3157, "$noep8", "b9beede7f0d05ee657501cea72e1a453"]
      ]
    end

    it "should raise an error if scanning an invalid file" do
      @rules.compile_file(sample_file("packers.yara"))
      lambda { @rules.scan_file(sample_file("not a real file at all")) }.should raise_error(Yara::ScanError)
      lambda { @rules.scan_file(Object.new)}.should raise_error(TypeError)
      lambda { @rules.scan_file(nil)}.should raise_error(TypeError)
    end

    it "should raise an error if scanning a zero-length file" do
      @rules.compile_file(sample_file("packers.yara"))
      lambda { @rules.scan_file("/dev/null")}.should raise_error(Yara::ScanError)
    end

    it "should scan a string" do
      @rules.compile_file(sample_file("packers.yara"))
      results = @rules.scan_string(File.read(sample_file("DumpMem.exe")))
      results.should be_kind_of(Array)
      results.size.should == 1
      m = results.first
      m.should be_kind_of(Yara::Match)
      m.should be_frozen

      m.rule.should == "UPX"
      m.rule.should be_frozen

      m.namespace.should == "default"
      m.namespace.should be_frozen

      m.tags.should == ["compression", "packer", "shady"]
      m.tags.should be_frozen
      m.tags.map{|v| v.should be_frozen }

      m.strings.should be_frozen
      strings = m.strings.sort
      strings.each do |ms| 
        ms.should be_kind_of(Yara::MatchString)
        ms.identifier.should be_frozen
        ms.buffer.should be_frozen
      end

      strings.map{|ms| [ms.offset, ms.identifier, md5(ms.buffer)] }.should == [
        [2824, "$noep5", "af79592a2fc536596fcbe87409734626"],
        [2830, "$noep3", "04b044f4bfeb6899b6b60ff7d6b1d103"],
        [3010, "$noep2", "8711f47b104922246e5733211cd832b1"],
        [3110, "$noep7", "71be53d1049f47219ad8f26a77255229"],
        [3157, "$noep8", "b9beede7f0d05ee657501cea72e1a453"]
      ]

    end


    it "should raise an error if scanning an invalid string" do
      @rules.compile_file(sample_file("packers.yara"))
      lambda { @rules.scan_string(Object.new)}.should raise_error(TypeError)
      lambda { @rules.scan_string(nil)}.should raise_error(TypeError)
    end


    it "should take an optional namespace when compiling a file" do
      @rules.compile_file(sample_file("packers.yara"), "an_optional_namespace1" )
      results = @rules.scan_file(sample_file("DumpMem.exe"))
      results.should be_kind_of(Array)
      results.size.should == 1

      m = results.first
      m.should be_kind_of(Yara::Match)
      m.should be_frozen

      m.rule.should == "UPX"

      m.namespace.should == "an_optional_namespace1"
      m.namespace.should be_frozen

      #@rules.current_namespace.should == "an_optional_namespace1"
    end

    it "should allow the 'default' namespace when compiling a file" do
      @rules.compile_file(sample_file("packers.yara"), "default" )
      results = @rules.scan_file(sample_file("DumpMem.exe"))
      results.should be_kind_of(Array)
      results.size.should == 1

      m = results.first
      m.should be_kind_of(Yara::Match)
      m.should be_frozen

      m.rule.should == "UPX"

      m.namespace.should == "default"
      m.namespace.should be_frozen

      #@rules.current_namespace.should == "default"
    end

    it "should raise an error when compiling a file with an invalid namespace" do
      lambda { @rules.compile_file(sample_file("packers.yara"), 1) }.should raise_error(TypeError)
    end


    it "should take an optional namespace and change the current namespace when compiling a string" do
      @rules.compile_string(File.read(sample_file("packers.yara")), "an_optional_namespace2")
      results = @rules.scan_file(sample_file("DumpMem.exe"))
      results.should be_kind_of(Array)
      results.size.should == 1

      m = results.first
      m.should be_kind_of(Yara::Match)
      m.should be_frozen

      m.rule.should == "UPX"

      m.namespace.should == "an_optional_namespace2"
      m.namespace.should be_frozen

      #@rules.current_namespace.should == "an_optional_namespace2"
    end

    it "should allow the 'default' namespace when compiling a string" do
      @rules.compile_string(File.read(sample_file("packers.yara")), "default")
      results = @rules.scan_file(sample_file("DumpMem.exe"))
      results.should be_kind_of(Array)
      results.size.should == 1

      m = results.first
      m.should be_kind_of(Yara::Match)
      m.should be_frozen

      m.rule.should == "UPX"

      m.namespace.should == "default"
      m.namespace.should be_frozen

      #@rules.current_namespace.should == "default"
    end


    it "should raise an error when compiling a string with an invalid namespace" do
      lambda { @rules.compile_string(File.read(sample_file("packers.yara")), 1) }.should raise_error(TypeError)
    end

  end
end
