/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.TrustedPtr;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with drm
 */
@java.lang.SuppressWarnings("unused")
public final class DrmDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_bridge_duplicate_state(Ptr<drm_bridge> bridge,
      Ptr<drm_bridge_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_bridge_reset(Ptr<drm_bridge> bridge,
      Ptr<drm_bridge_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_connector_destroy_state(Ptr<drm_connector_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_connector_duplicate_state(Ptr<drm_connector> connector,
      Ptr<drm_connector_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_connector_reset(Ptr<drm_connector> connector,
      Ptr<drm_connector_state> conn_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_connector_state_reset(Ptr<drm_connector_state> conn_state,
      Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_crtc_destroy_state(Ptr<drm_crtc_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_crtc_duplicate_state(Ptr<drm_crtc> crtc,
      Ptr<drm_crtc_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_crtc_reset(Ptr<drm_crtc> crtc,
      Ptr<drm_crtc_state> crtc_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_crtc_state_reset(Ptr<drm_crtc_state> crtc_state,
      Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __drm_atomic_helper_disable_plane(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_plane_destroy_state(Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_plane_duplicate_state(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_plane_reset(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_plane_state_reset(Ptr<drm_plane_state> plane_state,
      Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_helper_private_obj_duplicate_state(Ptr<drm_private_obj> obj,
      Ptr<drm_private_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __drm_atomic_helper_set_config(Ptr<drm_mode_set> set,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_atomic_state_free(Ptr<kref> ref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_connector_put_safe(Ptr<drm_connector> conn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_crtc_commit_free(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_crtc_init_with_planes($arg1, $arg2, $arg3, $arg4, (const struct drm_crtc_funcs *)$arg5, (const u8 *)$arg6, $arg7)")
  public static int __drm_crtc_init_with_planes(Ptr<drm_device> dev, Ptr<drm_crtc> crtc,
      Ptr<drm_plane> primary, Ptr<drm_plane> cursor, Ptr<drm_crtc_funcs> funcs, String name,
      Ptr<__va_list_tag> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_dev_alloc($arg1, (const struct drm_driver *)$arg2, $arg3, $arg4)")
  public static Ptr<?> __drm_dev_alloc(Ptr<device> parent, Ptr<drm_driver> driver,
      @Unsigned long size, @Unsigned long offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_dev_dbg($arg1, (const struct device *)$arg2, $arg3, (const u8 *)$arg4, $arg5_)")
  public static void __drm_dev_dbg(Ptr<_ddebug> desc, Ptr<device> dev, drm_debug_category category,
      String format, java.lang.Object... param4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_dev_vprintk((const struct device *)$arg1, (const u8 *)$arg2, (const void *)$arg3, (const u8 *)$arg4, $arg5)")
  public static void __drm_dev_vprintk(Ptr<device> dev, String level, Ptr<?> origin, String prefix,
      Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const void*)__drm_edid_iter_next($arg1))")
  public static Ptr<?> __drm_edid_iter_next(Ptr<drm_edid_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_encoder_init($arg1, $arg2, (const struct drm_encoder_funcs *)$arg3, $arg4, (const u8 *)$arg5, $arg6)")
  public static int __drm_encoder_init(Ptr<drm_device> dev, Ptr<drm_encoder> encoder,
      Ptr<drm_encoder_funcs> funcs, int encoder_type, String name, Ptr<__va_list_tag> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_err((const u8 *)$arg1, $arg2_)")
  public static void __drm_err(String format, java.lang.Object... param1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __drm_fb_helper_find_sizes(Ptr<drm_fb_helper> fb_helper,
      Ptr<drm_fb_helper_surface_size> sizes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __drm_fb_helper_initial_config_and_unlock(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __drm_fb_helper_restore_fbdev_mode_unlocked(Ptr<drm_fb_helper> fb_helper,
      boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_fb_xfrm($arg1, $arg2, $arg3, (const void *)$arg4, (const struct drm_framebuffer *)$arg5, (const struct drm_rect *)$arg6, $arg7, $arg8, (void (*)(void*, const void*, unsigned int))$arg9)")
  public static int __drm_fb_xfrm(Ptr<?> dst, @Unsigned long dst_pitch, @Unsigned long dst_pixsize,
      Ptr<?> vaddr, Ptr<drm_framebuffer> fb, Ptr<drm_rect> clip, boolean vaddr_cached_hint,
      Ptr<drm_format_conv_state> state, Ptr<?> xfrm_line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_fb_xfrm_toio($arg1, $arg2, $arg3, (const void *)$arg4, (const struct drm_framebuffer *)$arg5, (const struct drm_rect *)$arg6, $arg7, $arg8, (void (*)(void*, const void*, unsigned int))$arg9)")
  public static int __drm_fb_xfrm_toio(Ptr<?> dst, @Unsigned long dst_pitch,
      @Unsigned long dst_pixsize, Ptr<?> vaddr, Ptr<drm_framebuffer> fb, Ptr<drm_rect> clip,
      boolean vaddr_cached_hint, Ptr<drm_format_conv_state> state, Ptr<?> xfrm_line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_format_info*)__drm_format_info($arg1))")
  public static Ptr<drm_format_info> __drm_format_info(@Unsigned int format) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_gem_destroy_shadow_plane_state(
      Ptr<drm_shadow_plane_state> shadow_plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_gem_duplicate_shadow_plane_state(Ptr<drm_plane> plane,
      Ptr<drm_shadow_plane_state> new_shadow_plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_gem_fb_end_cpu_access(Ptr<drm_framebuffer> fb, dma_data_direction dir,
      @Unsigned int num_planes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_gem_reset_shadow_plane(Ptr<drm_plane> plane,
      Ptr<drm_shadow_plane_state> shadow_plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_gem_shmem_object> __drm_gem_shmem_create(Ptr<drm_device> dev,
      @Unsigned long size, boolean _private, Ptr<vfsmount> gemfs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_helper_disable_unused_functions(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __drm_helper_update_and_validate(Ptr<drm_connector> connector,
      @Unsigned @OriginalName("uint32_t") int maxX, @Unsigned @OriginalName("uint32_t") int maxY,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_memcpy_from_wc($arg1, (const void *)$arg2, $arg3)")
  public static void __drm_memcpy_from_wc(Ptr<?> dst, Ptr<?> src, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_mm_interval_first((const struct drm_mm *)$arg1, $arg2, $arg3)")
  public static Ptr<drm_mm_node> __drm_mm_interval_first(Ptr<drm_mm> mm, @Unsigned long start,
      @Unsigned long last) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_mode_object_add($arg1, $arg2, $arg3, $arg4, (void (*)(struct kref*))$arg5)")
  public static int __drm_mode_object_add(Ptr<drm_device> dev, Ptr<drm_mode_object> obj,
      @Unsigned @OriginalName("uint32_t") int obj_type, boolean register_obj, Ptr<?> obj_free_cb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_mode_object> __drm_mode_object_find(Ptr<drm_device> dev,
      Ptr<drm_file> file_priv, @Unsigned @OriginalName("uint32_t") int id,
      @Unsigned @OriginalName("uint32_t") int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __drm_mode_set_config_internal(Ptr<drm_mode_set> set,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __drm_object_property_get_value(Ptr<drm_mode_object> obj,
      Ptr<drm_property> property, Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_plane_get_damage_clips((const struct drm_plane_state *)$arg1)")
  public static Ptr<drm_mode_rect> __drm_plane_get_damage_clips(Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_printfn_coredump(Ptr<drm_printer> p, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_printfn_dbg(Ptr<drm_printer> p, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_printfn_err(Ptr<drm_printer> p, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_printfn_info(Ptr<drm_printer> p, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_printfn_line(Ptr<drm_printer> p, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_printfn_seq_file(Ptr<drm_printer> p, Ptr<va_format> vaf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_puts_coredump($arg1, (const u8 *)$arg2)")
  public static void __drm_puts_coredump(Ptr<drm_printer> p, String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_puts_seq_file($arg1, (const u8 *)$arg2)")
  public static void __drm_puts_seq_file(Ptr<drm_printer> p, String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __drm_state_dump(Ptr<drm_device> dev, Ptr<drm_printer> p, boolean take_locks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_universal_plane_alloc($arg1, $arg2, $arg3, $arg4, (const struct drm_plane_funcs *)$arg5, (const unsigned int *)$arg6, $arg7, (const long long unsigned int *)$arg8, $arg9, (const u8 *)$arg10, $arg11_)")
  public static Ptr<?> __drm_universal_plane_alloc(Ptr<drm_device> dev, @Unsigned long size,
      @Unsigned long offset, @Unsigned @OriginalName("uint32_t") int possible_crtcs,
      Ptr<drm_plane_funcs> funcs,
      Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> formats,
      @Unsigned int format_count,
      Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> format_modifiers,
      drm_plane_type type, String name, java.lang.Object... param10) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_universal_plane_init($arg1, $arg2, $arg3, (const struct drm_plane_funcs *)$arg4, (const unsigned int *)$arg5, $arg6, (const long long unsigned int *)$arg7, $arg8, (const u8 *)$arg9, $arg10)")
  public static int __drm_universal_plane_init(Ptr<drm_device> dev, Ptr<drm_plane> plane,
      @Unsigned @OriginalName("uint32_t") int possible_crtcs, Ptr<drm_plane_funcs> funcs,
      Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> formats,
      @Unsigned int format_count,
      Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> format_modifiers,
      drm_plane_type type, String name, Ptr<__va_list_tag> ap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__drm_writeback_connector_init($arg1, $arg2, $arg3, (const unsigned int *)$arg4, $arg5)")
  public static int __drm_writeback_connector_init(Ptr<drm_device> dev,
      Ptr<drm_writeback_connector> wb_connector, Ptr<drm_encoder> enc,
      Ptr<java.lang. @Unsigned Integer> formats, int n_formats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<edid> _drm_do_get_edid(Ptr<drm_connector> connector, Ptr<?> read_block,
      Ptr<?> context, Ptr<java.lang. @Unsigned Long> size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)_drm_edid_alloc((const void *)$arg1, $arg2))")
  public static Ptr<drm_edid> _drm_edid_alloc(Ptr<?> edid, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("_drm_edid_connector_add_modes($arg1, (const struct drm_edid *)$arg2)")
  public static int _drm_edid_connector_add_modes(Ptr<drm_connector> connector,
      Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("_drm_edid_connector_property_update($arg1, (const struct drm_edid *)$arg2)")
  public static int _drm_edid_connector_property_update(Ptr<drm_connector> connector,
      Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("_drm_edid_to_sad((const struct drm_edid *)$arg1, $arg2)")
  public static int _drm_edid_to_sad(Ptr<drm_edid> drm_edid, Ptr<Ptr<cea_sad>> psads) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean _drm_lease_held(Ptr<drm_file> file_priv, int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void _drm_lease_revoke(Ptr<drm_master> top) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_add_edid_modes(Ptr<drm_connector> connector, Ptr<edid> edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_add_modes_noedid(Ptr<drm_connector> connector, @Unsigned int hdisplay,
      @Unsigned int vdisplay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_display_mode> drm_analog_tv_mode(Ptr<drm_device> dev,
      drm_connector_tv_mode tv_mode, @Unsigned long pixel_clock_hz, @Unsigned int hdisplay,
      @Unsigned int vdisplay, boolean interlace) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_any_plane_has_format(Ptr<drm_device> dev, @Unsigned int format,
      @Unsigned long modifier) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_add_affected_connectors(Ptr<drm_atomic_state> state,
      Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_add_affected_planes(Ptr<drm_atomic_state> state,
      Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_add_encoder_bridges(Ptr<drm_atomic_state> state,
      Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_bridge_call_post_disable(Ptr<drm_bridge> bridge,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_bridge_call_pre_enable(Ptr<drm_bridge> bridge,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_bridge_chain_check(Ptr<drm_bridge> bridge,
      Ptr<drm_crtc_state> crtc_state, Ptr<drm_connector_state> conn_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_bridge_chain_disable(Ptr<drm_bridge> bridge,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_bridge_chain_enable(Ptr<drm_bridge> bridge,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_bridge_chain_post_disable(Ptr<drm_bridge> bridge,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_bridge_chain_pre_enable(Ptr<drm_bridge> bridge,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_check_only(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_commit(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_connector_check(Ptr<drm_connector> connector,
      Ptr<drm_connector_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_connector_commit_dpms(Ptr<drm_atomic_state> state,
      Ptr<drm_connector> connector, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_connector_get_property($arg1, (const struct drm_connector_state *)$arg2, $arg3, $arg4)")
  public static int drm_atomic_connector_get_property(Ptr<drm_connector> connector,
      Ptr<drm_connector_state> state, Ptr<drm_property> property,
      Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_connector_print_state($arg1, (const struct drm_connector_state *)$arg2)")
  public static void drm_atomic_connector_print_state(Ptr<drm_printer> p,
      Ptr<drm_connector_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_connector_set_property(Ptr<drm_connector> connector,
      Ptr<drm_connector_state> state, Ptr<drm_file> file_priv, Ptr<drm_property> property,
      @Unsigned @OriginalName("uint64_t") long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_crtc_check((const struct drm_crtc_state *)$arg1, (const struct drm_crtc_state *)$arg2)")
  public static int drm_atomic_crtc_check(Ptr<drm_crtc_state> old_crtc_state,
      Ptr<drm_crtc_state> new_crtc_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_crtc_get_property($arg1, (const struct drm_crtc_state *)$arg2, $arg3, $arg4)")
  public static int drm_atomic_crtc_get_property(Ptr<drm_crtc> crtc, Ptr<drm_crtc_state> state,
      Ptr<drm_property> property, Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_crtc_print_state($arg1, (const struct drm_crtc_state *)$arg2)")
  public static void drm_atomic_crtc_print_state(Ptr<drm_printer> p, Ptr<drm_crtc_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_crtc_set_property(Ptr<drm_crtc> crtc, Ptr<drm_crtc_state> state,
      Ptr<drm_property> property, @Unsigned @OriginalName("uint64_t") long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_debugfs_init(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_bridge_state> drm_atomic_get_bridge_state(Ptr<drm_atomic_state> state,
      Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_get_connector_for_encoder((const struct drm_encoder *)$arg1, $arg2)")
  public static Ptr<drm_connector> drm_atomic_get_connector_for_encoder(Ptr<drm_encoder> encoder,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_connector_state> drm_atomic_get_connector_state(Ptr<drm_atomic_state> state,
      Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_crtc_state> drm_atomic_get_crtc_state(Ptr<drm_atomic_state> state,
      Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_get_new_bridge_state((const struct drm_atomic_state *)$arg1, $arg2)")
  public static Ptr<drm_bridge_state> drm_atomic_get_new_bridge_state(Ptr<drm_atomic_state> state,
      Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_get_new_connector_for_encoder((const struct drm_atomic_state *)$arg1, $arg2)")
  public static Ptr<drm_connector> drm_atomic_get_new_connector_for_encoder(
      Ptr<drm_atomic_state> state, Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_crtc> drm_atomic_get_new_crtc_for_encoder(Ptr<drm_atomic_state> state,
      Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_get_new_private_obj_state((const struct drm_atomic_state *)$arg1, $arg2)")
  public static Ptr<drm_private_state> drm_atomic_get_new_private_obj_state(
      Ptr<drm_atomic_state> state, Ptr<drm_private_obj> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_get_old_bridge_state((const struct drm_atomic_state *)$arg1, $arg2)")
  public static Ptr<drm_bridge_state> drm_atomic_get_old_bridge_state(Ptr<drm_atomic_state> state,
      Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_get_old_connector_for_encoder((const struct drm_atomic_state *)$arg1, $arg2)")
  public static Ptr<drm_connector> drm_atomic_get_old_connector_for_encoder(
      Ptr<drm_atomic_state> state, Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_crtc> drm_atomic_get_old_crtc_for_encoder(Ptr<drm_atomic_state> state,
      Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_get_old_private_obj_state((const struct drm_atomic_state *)$arg1, $arg2)")
  public static Ptr<drm_private_state> drm_atomic_get_old_private_obj_state(
      Ptr<drm_atomic_state> state, Ptr<drm_private_obj> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_plane_state> drm_atomic_get_plane_state(Ptr<drm_atomic_state> state,
      Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_private_state> drm_atomic_get_private_obj_state(Ptr<drm_atomic_state> state,
      Ptr<drm_private_obj> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_get_property(Ptr<drm_mode_object> obj, Ptr<drm_property> property,
      Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_async_check(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_async_commit(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_bridge_destroy_state(Ptr<drm_bridge> bridge,
      Ptr<drm_bridge_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_bridge_state> drm_atomic_helper_bridge_duplicate_state(
      Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<java.lang. @Unsigned Integer> drm_atomic_helper_bridge_propagate_bus_fmt(
      Ptr<drm_bridge> bridge, Ptr<drm_bridge_state> bridge_state, Ptr<drm_crtc_state> crtc_state,
      Ptr<drm_connector_state> conn_state, @Unsigned int output_fmt,
      Ptr<java.lang. @Unsigned Integer> num_input_fmts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_bridge_state> drm_atomic_helper_bridge_reset(Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_calc_timestamping_constants(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_check(Ptr<drm_device> dev, Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_check_crtc_primary_plane(Ptr<drm_crtc_state> crtc_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_check_modeset(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_check_plane_damage(Ptr<drm_atomic_state> state,
      Ptr<drm_plane_state> plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_helper_check_plane_state($arg1, (const struct drm_crtc_state *)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static int drm_atomic_helper_check_plane_state(Ptr<drm_plane_state> plane_state,
      Ptr<drm_crtc_state> crtc_state, int min_scale, int max_scale, boolean can_position,
      boolean can_update_disabled) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_check_planes(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_check_wb_connector_state(Ptr<drm_connector> connector,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_cleanup_planes(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_commit(Ptr<drm_device> dev, Ptr<drm_atomic_state> state,
      boolean nonblock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_commit_cleanup_done(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_commit_duplicated_state(Ptr<drm_atomic_state> state,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_commit_hw_done(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_commit_modeset_disables(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_commit_modeset_enables(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_commit_planes(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state, @Unsigned @OriginalName("uint32_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_commit_planes_on_crtc(Ptr<drm_crtc_state> old_crtc_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_commit_tail(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_commit_tail_rpm(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_connector_destroy_state(Ptr<drm_connector> connector,
      Ptr<drm_connector_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_connector_state> drm_atomic_helper_connector_duplicate_state(
      Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_connector_reset(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_connector_tv_check(Ptr<drm_connector> connector,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_connector_tv_margins_reset(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_connector_tv_reset(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_crtc_destroy_state(Ptr<drm_crtc> crtc,
      Ptr<drm_crtc_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_crtc_state> drm_atomic_helper_crtc_duplicate_state(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_crtc_normalize_zpos(Ptr<drm_crtc> crtc,
      Ptr<drm_crtc_state> crtc_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_crtc_reset(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_helper_damage_iter_init($arg1, (const struct drm_plane_state *)$arg2, (const struct drm_plane_state *)$arg3)")
  public static void drm_atomic_helper_damage_iter_init(Ptr<drm_atomic_helper_damage_iter> iter,
      Ptr<drm_plane_state> old_state, Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_atomic_helper_damage_iter_next(Ptr<drm_atomic_helper_damage_iter> iter,
      Ptr<drm_rect> rect) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_helper_damage_merged((const struct drm_plane_state *)$arg1, (const struct drm_plane_state *)$arg2, $arg3)")
  public static boolean drm_atomic_helper_damage_merged(Ptr<drm_plane_state> old_state,
      Ptr<drm_plane_state> state, Ptr<drm_rect> rect) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_dirtyfb(Ptr<drm_framebuffer> fb, Ptr<drm_file> file_priv,
      @Unsigned int flags, @Unsigned int color, Ptr<drm_clip_rect> clips, @Unsigned int num_clips) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_disable_all(Ptr<drm_device> dev,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_disable_plane(Ptr<drm_plane> plane,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_disable_planes_on_crtc(Ptr<drm_crtc_state> old_crtc_state,
      boolean atomic) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_atomic_state> drm_atomic_helper_duplicate_state(Ptr<drm_device> dev,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_fake_vblank(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_page_flip(Ptr<drm_crtc> crtc, Ptr<drm_framebuffer> fb,
      Ptr<drm_pending_vblank_event> event, @Unsigned @OriginalName("uint32_t") int flags,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_page_flip_target(Ptr<drm_crtc> crtc, Ptr<drm_framebuffer> fb,
      Ptr<drm_pending_vblank_event> event, @Unsigned @OriginalName("uint32_t") int flags,
      @Unsigned @OriginalName("uint32_t") int target, Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_plane_destroy_state(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_plane_state> drm_atomic_helper_plane_duplicate_state(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_plane_reset(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_prepare_planes(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_reset_crtc(Ptr<drm_crtc> crtc,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_resume(Ptr<drm_device> dev, Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_set_config(Ptr<drm_mode_set> set,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_setup_commit(Ptr<drm_atomic_state> state, boolean nonblock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_shutdown(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_atomic_state> drm_atomic_helper_suspend(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_swap_state(Ptr<drm_atomic_state> state, boolean stall) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_unprepare_planes(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_update_legacy_modeset_state(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_update_plane(Ptr<drm_plane> plane, Ptr<drm_crtc> crtc,
      Ptr<drm_framebuffer> fb, int crtc_x, int crtc_y, @Unsigned int crtc_w, @Unsigned int crtc_h,
      @Unsigned @OriginalName("uint32_t") int src_x, @Unsigned @OriginalName("uint32_t") int src_y,
      @Unsigned @OriginalName("uint32_t") int src_w, @Unsigned @OriginalName("uint32_t") int src_h,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_wait_for_dependencies(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_helper_wait_for_fences(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state, boolean pre_swap) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_wait_for_flip_done(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_helper_wait_for_vblanks(Ptr<drm_device> dev,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_nonblocking_commit(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_normalize_zpos(Ptr<drm_device> dev, Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_plane_check((const struct drm_plane_state *)$arg1, (const struct drm_plane_state *)$arg2)")
  public static int drm_atomic_plane_check(Ptr<drm_plane_state> old_plane_state,
      Ptr<drm_plane_state> new_plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_plane_get_property($arg1, (const struct drm_plane_state *)$arg2, $arg3, $arg4)")
  public static int drm_atomic_plane_get_property(Ptr<drm_plane> plane, Ptr<drm_plane_state> state,
      Ptr<drm_property> property, Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_plane_print_state($arg1, (const struct drm_plane_state *)$arg2)")
  public static void drm_atomic_plane_print_state(Ptr<drm_printer> p, Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_plane_set_property(Ptr<drm_plane> plane, Ptr<drm_plane_state> state,
      Ptr<drm_file> file_priv, Ptr<drm_property> property,
      @Unsigned @OriginalName("uint64_t") long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_print_new_state((const struct drm_atomic_state *)$arg1, $arg2)")
  public static void drm_atomic_print_new_state(Ptr<drm_atomic_state> state, Ptr<drm_printer> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_private_obj_fini(Ptr<drm_private_obj> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_private_obj_init($arg1, $arg2, $arg3, (const struct drm_private_state_funcs *)$arg4)")
  public static void drm_atomic_private_obj_init(Ptr<drm_device> dev, Ptr<drm_private_obj> obj,
      Ptr<drm_private_state> state, Ptr<drm_private_state_funcs> funcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_set_crtc_for_connector(Ptr<drm_connector_state> conn_state,
      Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_set_crtc_for_plane(Ptr<drm_plane_state> plane_state,
      Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_set_fb_for_plane(Ptr<drm_plane_state> plane_state,
      Ptr<drm_framebuffer> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_set_mode_for_crtc($arg1, (const struct drm_display_mode *)$arg2)")
  public static int drm_atomic_set_mode_for_crtc(Ptr<drm_crtc_state> state,
      Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_set_mode_prop_for_crtc(Ptr<drm_crtc_state> state,
      Ptr<drm_property_blob> blob) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_set_property(Ptr<drm_atomic_state> state, Ptr<drm_file> file_priv,
      Ptr<drm_mode_object> obj, Ptr<drm_property> prop, @Unsigned long prop_value,
      boolean async_flip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_atomic_state> drm_atomic_state_alloc(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_state_clear(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_state_default_clear(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_atomic_state_default_release(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_atomic_state_init(Ptr<drm_device> dev, Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_atomic_state_zpos_cmp((const void *)$arg1, (const void *)$arg2)")
  public static int drm_atomic_state_zpos_cmp(Ptr<?> a, Ptr<?> b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_authmagic(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_av_sync_delay($arg1, (const struct drm_display_mode *)$arg2)")
  public static int drm_av_sync_delay(Ptr<drm_connector> connector, Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_add(Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_atomic_destroy_priv_state(Ptr<drm_private_obj> obj,
      Ptr<drm_private_state> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_private_state> drm_bridge_atomic_duplicate_priv_state(
      Ptr<drm_private_obj> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_bridge_attach(Ptr<drm_encoder> encoder, Ptr<drm_bridge> bridge,
      Ptr<drm_bridge> previous, drm_bridge_attach_flags flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_bridge_chain_mode_set($arg1, (const struct drm_display_mode *)$arg2, (const struct drm_display_mode *)$arg3)")
  public static void drm_bridge_chain_mode_set(Ptr<drm_bridge> bridge, Ptr<drm_display_mode> mode,
      Ptr<drm_display_mode> adjusted_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_bridge_chain_mode_valid($arg1, (const struct drm_display_info *)$arg2, (const struct drm_display_mode *)$arg3)")
  public static drm_mode_status drm_bridge_chain_mode_valid(Ptr<drm_bridge> bridge,
      Ptr<drm_display_info> info, Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_debugfs_encoder_params(Ptr<dentry> root, Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_debugfs_params(Ptr<dentry> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_debugfs_show_bridge(Ptr<drm_printer> p, Ptr<drm_bridge> bridge,
      @Unsigned int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_detach(Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static drm_connector_status drm_bridge_detect(Ptr<drm_bridge> bridge,
      Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_bridge_edid_read($arg1, $arg2))")
  public static Ptr<drm_edid> drm_bridge_edid_read(Ptr<drm_bridge> bridge,
      Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_bridge> drm_bridge_get(Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_bridge_get_modes(Ptr<drm_bridge> bridge, Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_bridge_helper_reset_crtc(Ptr<drm_bridge> bridge,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_hpd_disable(Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_bridge_hpd_enable($arg1, (void (*)(void*, enum drm_connector_status))$arg2, $arg3)")
  public static void drm_bridge_hpd_enable(Ptr<drm_bridge> bridge, Ptr<?> cb, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_hpd_notify(Ptr<drm_bridge> bridge, drm_connector_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_bridge_is_panel((const struct drm_bridge *)$arg1)")
  public static boolean drm_bridge_is_panel(Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_put(Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_put_void(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_remove(Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_bridge_remove_void(Ptr<?> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_bus_flags_from_videomode((const struct videomode *)$arg1, $arg2)")
  public static void drm_bus_flags_from_videomode(Ptr<videomode> vm,
      Ptr<java.lang. @Unsigned Integer> bus_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_calc_timestamping_constants($arg1, (const struct drm_display_mode *)$arg2)")
  public static void drm_calc_timestamping_constants(Ptr<drm_crtc> crtc,
      Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_can_sleep() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_class_device_register(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_class_device_unregister(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_clflush_page(Ptr<page> page) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_clflush_pages(Ptr<Ptr<page>> pages, @Unsigned long num_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_clflush_sg(Ptr<sg_table> st) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_clflush_virt_range(Ptr<?> addr, @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_buffer_addfb(Ptr<drm_client_buffer> buffer, @Unsigned int width,
      @Unsigned int height, @Unsigned int format, @Unsigned int handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_buffer_delete(Ptr<drm_client_buffer> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_buffer_vmap(Ptr<drm_client_buffer> buffer, Ptr<iosys_map> map_copy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_buffer_vmap_local(Ptr<drm_client_buffer> buffer,
      Ptr<iosys_map> map_copy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_buffer_vunmap(Ptr<drm_client_buffer> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_buffer_vunmap_local(Ptr<drm_client_buffer> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_connectors_enabled(Ptr<Ptr<drm_connector>> connectors,
      @Unsigned int connector_count, Ptr<java.lang. @OriginalName("bool") Boolean> enabled) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_debugfs_init(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_debugfs_internal_clients(Ptr<seq_file> m, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_dev_hotplug(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_dev_restore(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_dev_resume(Ptr<drm_device> dev, boolean holds_console_lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_dev_suspend(Ptr<drm_device> dev, boolean holds_console_lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_dev_unregister(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_client_buffer> drm_client_framebuffer_create(Ptr<drm_client_dev> client,
      @Unsigned int width, @Unsigned int height, @Unsigned int format) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_framebuffer_delete(Ptr<drm_client_buffer> buffer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_framebuffer_flush(Ptr<drm_client_buffer> buffer,
      Ptr<drm_rect> rect) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_client_get_tile_offsets($arg1, $arg2, $arg3, (const struct drm_display_mode**)$arg4, $arg5, $arg6, $arg7, $arg8)")
  public static int drm_client_get_tile_offsets(Ptr<drm_device> dev,
      Ptr<Ptr<drm_connector>> connectors, @Unsigned int connector_count,
      Ptr<Ptr<drm_display_mode>> modes, Ptr<drm_client_offset> offsets, int idx, int h_idx,
      int v_idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_hotplug(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_client_init($arg1, $arg2, (const u8 *)$arg3, (const struct drm_client_funcs *)$arg4)")
  public static int drm_client_init(Ptr<drm_device> dev, Ptr<drm_client_dev> client, String name,
      Ptr<drm_client_funcs> funcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_modeset_check(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_modeset_commit(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_modeset_commit_atomic(Ptr<drm_client_dev> client, boolean active,
      boolean check) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_modeset_commit_locked(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_modeset_create(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_modeset_dpms(Ptr<drm_client_dev> client, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_modeset_free(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_client_modeset_probe(Ptr<drm_client_dev> client, @Unsigned int width,
      @Unsigned int height) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_modeset_release(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_client_pick_crtcs($arg1, $arg2, $arg3, $arg4, (const struct drm_display_mode**)$arg5, $arg6, $arg7, $arg8)")
  public static int drm_client_pick_crtcs(Ptr<drm_client_dev> client,
      Ptr<Ptr<drm_connector>> connectors, @Unsigned int connector_count,
      Ptr<Ptr<drm_crtc>> best_crtcs, Ptr<Ptr<drm_display_mode>> modes, int n, int width,
      int height) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_register(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_release(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_client_rotation(Ptr<drm_mode_set> modeset,
      Ptr<java.lang. @Unsigned Integer> rotation) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_client_setup($arg1, (const struct drm_format_info *)$arg2)")
  public static void drm_client_setup(Ptr<drm_device> dev, Ptr<drm_format_info> format) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_setup_with_color_mode(Ptr<drm_device> dev,
      @Unsigned int color_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_client_setup_with_fourcc(Ptr<drm_device> dev, @Unsigned int fourcc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_client_target_preferred($arg1, $arg2, $arg3, (const struct drm_display_mode**)$arg4, $arg5, $arg6, $arg7, $arg8)")
  public static boolean drm_client_target_preferred(Ptr<drm_device> dev,
      Ptr<Ptr<drm_connector>> connectors, @Unsigned int connector_count,
      Ptr<Ptr<drm_display_mode>> modes, Ptr<drm_client_offset> offsets,
      Ptr<java.lang. @OriginalName("bool") Boolean> enabled, int width, int height) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_clients_info(Ptr<seq_file> m, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long drm_color_ctm_s31_32_to_qm_n(@Unsigned long user_input,
      @Unsigned int m, @Unsigned int n) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_color_lut_check((const struct drm_property_blob *)$arg1, $arg2)")
  public static int drm_color_lut_check(Ptr<drm_property_blob> lut, @Unsigned int tests) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long drm_compat_ioctl(Ptr<file> filp, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_connector_acpi_bus_match(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<acpi_device> drm_connector_acpi_find_companion(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_add(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_connector_atomic_hdr_metadata_equal(Ptr<drm_connector_state> old_state,
      Ptr<drm_connector_state> new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_attach_broadcast_rgb_property(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_attach_colorspace_property(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_attach_content_type_property(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_attach_dp_subconnector_property(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_attach_edid_property(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_attach_encoder(Ptr<drm_connector> connector,
      Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_attach_hdr_output_metadata_property(
      Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_attach_max_bpc_property(Ptr<drm_connector> connector, int min,
      int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_attach_privacy_screen_properties(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_attach_privacy_screen_provider(Ptr<drm_connector> connector,
      Ptr<drm_privacy_screen> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_attach_scaling_mode_property(Ptr<drm_connector> connector,
      @Unsigned int scaling_mode_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_attach_tv_margin_properties(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_attach_vrr_capable_property(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_cec_phys_addr_invalidate(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_cec_phys_addr_set(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_cleanup(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_cleanup_action(Ptr<drm_device> dev, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_create_privacy_screen_properties(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_create_standard_properties(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_connector_dynamic_init($arg1, $arg2, (const struct drm_connector_funcs *)$arg3, $arg4, $arg5)")
  public static int drm_connector_dynamic_init(Ptr<drm_device> dev, Ptr<drm_connector> connector,
      Ptr<drm_connector_funcs> funcs, int connector_type, Ptr<i2c_adapter> ddc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_dynamic_register(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_connector> drm_connector_find_by_fwnode(Ptr<fwnode_handle> fwnode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_free(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_free_work_fn(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_get_cmdline_mode(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_encoder> drm_connector_get_single_encoder(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_connector_has_possible_encoder(Ptr<drm_connector> connector,
      Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_helper_detect_from_ddc(Ptr<drm_connector> connector,
      Ptr<drm_modeset_acquire_ctx> ctx, boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_helper_get_modes(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_connector_helper_get_modes_fixed($arg1, (const struct drm_display_mode *)$arg2)")
  public static int drm_connector_helper_get_modes_fixed(Ptr<drm_connector> connector,
      Ptr<drm_display_mode> fixed_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_connector_helper_hpd_irq_event(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_helper_tv_get_modes(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_ida_destroy() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_ida_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_connector_init($arg1, $arg2, (const struct drm_connector_funcs *)$arg3, $arg4)")
  public static int drm_connector_init(Ptr<drm_device> dev, Ptr<drm_connector> connector,
      Ptr<drm_connector_funcs> funcs, int connector_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_connector_init_only($arg1, $arg2, (const struct drm_connector_funcs *)$arg3, $arg4, $arg5)")
  public static int drm_connector_init_only(Ptr<drm_device> dev, Ptr<drm_connector> connector,
      Ptr<drm_connector_funcs> funcs, int connector_type, Ptr<i2c_adapter> ddc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_connector_init_with_ddc($arg1, $arg2, (const struct drm_connector_funcs *)$arg3, $arg4, $arg5)")
  public static int drm_connector_init_with_ddc(Ptr<drm_device> dev, Ptr<drm_connector> connector,
      Ptr<drm_connector_funcs> funcs, int connector_type, Ptr<i2c_adapter> ddc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_list_iter_begin(Ptr<drm_device> dev,
      Ptr<drm_connector_list_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_list_iter_end(Ptr<drm_connector_list_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_connector> drm_connector_list_iter_next(Ptr<drm_connector_list_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_list_update(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_connector_mode_valid($arg1, (const struct drm_display_mode *)$arg2, $arg3, $arg4)")
  public static int drm_connector_mode_valid(Ptr<drm_connector> connector,
      Ptr<drm_display_mode> mode, Ptr<drm_modeset_acquire_ctx> ctx, Ptr<drm_mode_status> status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_oob_hotplug_event(Ptr<fwnode_handle> connector_fwnode,
      drm_connector_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_display_mode*)drm_connector_pick_cmdline_mode($arg1))")
  public static Ptr<drm_display_mode> drm_connector_pick_cmdline_mode(
      Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_privacy_screen_notifier(Ptr<notifier_block> nb,
      @Unsigned long action, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_property_set_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_register(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_register_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_set_link_status_property(Ptr<drm_connector> connector,
      @Unsigned @OriginalName("uint64_t") long link_status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_set_obj_prop(Ptr<drm_mode_object> obj, Ptr<drm_property> property,
      @Unsigned @OriginalName("uint64_t") long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_set_orientation_from_panel(Ptr<drm_connector> connector,
      Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_set_panel_orientation(Ptr<drm_connector> connector,
      drm_panel_orientation panel_orientation) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_set_panel_orientation_with_quirk(Ptr<drm_connector> connector,
      drm_panel_orientation panel_orientation, int width, int height) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_connector_set_path_property($arg1, (const u8 *)$arg2)")
  public static int drm_connector_set_path_property(Ptr<drm_connector> connector, String path) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_connector_set_tile_property(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_set_vrr_capable_property(Ptr<drm_connector> connector,
      boolean capable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_unregister(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_connector_unregister_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_connector_update_edid_property($arg1, (const struct edid *)$arg2)")
  public static int drm_connector_update_edid_property(Ptr<drm_connector> connector,
      Ptr<edid> edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_connector_update_privacy_screen((const struct drm_connector_state *)$arg1)")
  public static void drm_connector_update_privacy_screen(Ptr<drm_connector_state> connector_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_copy_field($arg1, $arg2, (const u8 *)$arg3)")
  public static int drm_copy_field(String buf, Ptr<java.lang. @Unsigned Long> buf_len,
      String value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_core_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_core_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_property> drm_create_scaling_filter_prop(Ptr<drm_device> dev,
      @Unsigned int supported_filters) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long drm_crtc_accurate_vblank_count(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_add_crc_entry(Ptr<drm_crtc> crtc, boolean has_frame,
      @Unsigned @OriginalName("uint32_t") int frame,
      Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> crcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_arm_vblank_event(Ptr<drm_crtc> crtc,
      Ptr<drm_pending_vblank_event> e) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_crtc_check_viewport((const struct drm_crtc *)$arg1, $arg2, $arg3, (const struct drm_display_mode *)$arg4, (const struct drm_framebuffer *)$arg5)")
  public static int drm_crtc_check_viewport(Ptr<drm_crtc> crtc, int x, int y,
      Ptr<drm_display_mode> mode, Ptr<drm_framebuffer> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_cleanup(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_commit_wait(Ptr<drm_crtc_commit> commit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> drm_crtc_create_fence(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_create_scaling_filter_property(Ptr<drm_crtc> crtc,
      @Unsigned int supported_filters) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_enable_color_mgmt(Ptr<drm_crtc> crtc,
      @Unsigned @OriginalName("uint") int degamma_lut_size, boolean has_ctm,
      @Unsigned @OriginalName("uint") int gamma_lut_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_crtc_fence_get_driver_name($arg1))")
  public static String drm_crtc_fence_get_driver_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_crtc_fence_get_timeline_name($arg1))")
  public static String drm_crtc_fence_get_timeline_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_fill_gamma_555(Ptr<drm_crtc> crtc,
      @OriginalName("drm_crtc_set_lut_func") Ptr<?> set_gamma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_fill_gamma_565(Ptr<drm_crtc> crtc,
      @OriginalName("drm_crtc_set_lut_func") Ptr<?> set_gamma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_fill_gamma_888(Ptr<drm_crtc> crtc,
      @OriginalName("drm_crtc_set_lut_func") Ptr<?> set_gamma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_fill_palette_8(Ptr<drm_crtc> crtc,
      @OriginalName("drm_crtc_set_lut_func") Ptr<?> set_palette) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_force_disable(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_crtc> drm_crtc_from_index(Ptr<drm_device> dev, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_crtc_get_last_vbltimestamp(Ptr<drm_crtc> crtc,
      Ptr<java.lang. @OriginalName("ktime_t") Long> tvblank, boolean in_vblank_irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_get_sequence_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_crtc_handle_vblank(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_helper_atomic_check(Ptr<drm_crtc> crtc, Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_crtc_helper_mode_valid_fixed($arg1, (const struct drm_display_mode *)$arg2, (const struct drm_display_mode *)$arg3)")
  public static drm_mode_status drm_crtc_helper_mode_valid_fixed(Ptr<drm_crtc> crtc,
      Ptr<drm_display_mode> mode, Ptr<drm_display_mode> fixed_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_helper_set_config(Ptr<drm_mode_set> set,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_crtc_helper_set_mode(Ptr<drm_crtc> crtc, Ptr<drm_display_mode> mode,
      int x, int y, Ptr<drm_framebuffer> old_fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_crtc_in_clone_mode(Ptr<drm_crtc_state> crtc_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_crtc_init($arg1, $arg2, (const struct drm_crtc_funcs *)$arg3)")
  public static int drm_crtc_init(Ptr<drm_device> dev, Ptr<drm_crtc> crtc,
      Ptr<drm_crtc_funcs> funcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_crtc_init_with_planes($arg1, $arg2, $arg3, $arg4, (const struct drm_crtc_funcs *)$arg5, (const u8 *)$arg6, $arg7_)")
  public static int drm_crtc_init_with_planes(Ptr<drm_device> dev, Ptr<drm_crtc> crtc,
      Ptr<drm_plane> primary, Ptr<drm_plane> cursor, Ptr<drm_crtc_funcs> funcs, String name,
      java.lang.Object... param6) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_legacy_gamma_set(Ptr<drm_crtc> crtc,
      Ptr<java.lang. @Unsigned Short> red, Ptr<java.lang. @Unsigned Short> green,
      Ptr<java.lang. @Unsigned Short> blue, @Unsigned int size, Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_crtc_load_gamma_555_from_888($arg1, (const struct drm_color_lut *)$arg2, $arg3)")
  public static void drm_crtc_load_gamma_555_from_888(Ptr<drm_crtc> crtc, Ptr<drm_color_lut> lut,
      @OriginalName("drm_crtc_set_lut_func") Ptr<?> set_gamma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_crtc_load_gamma_565_from_888($arg1, (const struct drm_color_lut *)$arg2, $arg3)")
  public static void drm_crtc_load_gamma_565_from_888(Ptr<drm_crtc> crtc, Ptr<drm_color_lut> lut,
      @OriginalName("drm_crtc_set_lut_func") Ptr<?> set_gamma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_crtc_load_gamma_888($arg1, (const struct drm_color_lut *)$arg2, $arg3)")
  public static void drm_crtc_load_gamma_888(Ptr<drm_crtc> crtc, Ptr<drm_color_lut> lut,
      @OriginalName("drm_crtc_set_lut_func") Ptr<?> set_gamma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_crtc_load_palette_8($arg1, (const struct drm_color_lut *)$arg2, $arg3)")
  public static void drm_crtc_load_palette_8(Ptr<drm_crtc> crtc, Ptr<drm_color_lut> lut,
      @OriginalName("drm_crtc_set_lut_func") Ptr<?> set_palette) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_crtc_mode_valid($arg1, (const struct drm_display_mode *)$arg2)")
  public static drm_mode_status drm_crtc_mode_valid(Ptr<drm_crtc> crtc,
      Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_next_vblank_start(Ptr<drm_crtc> crtc,
      Ptr<java.lang. @OriginalName("ktime_t") Long> vblanktime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_queue_sequence_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_register_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_send_vblank_event(Ptr<drm_crtc> crtc,
      Ptr<drm_pending_vblank_event> e) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_set_max_vblank_count(Ptr<drm_crtc> crtc,
      @Unsigned int max_vblank_count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_unregister_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long drm_crtc_vblank_count(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long drm_crtc_vblank_count_and_time(Ptr<drm_crtc> crtc,
      Ptr<java.lang. @OriginalName("ktime_t") Long> vblanktime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_vblank_crtc> drm_crtc_vblank_crtc(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_crtc_vblank_get(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_crtc_vblank_helper_get_vblank_timestamp(Ptr<drm_crtc> crtc,
      Ptr<java.lang.Integer> max_error, Ptr<java.lang. @OriginalName("ktime_t") Long> vblank_time,
      boolean in_vblank_irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_crtc_vblank_helper_get_vblank_timestamp_internal(Ptr<drm_crtc> crtc,
      Ptr<java.lang.Integer> max_error, Ptr<java.lang. @OriginalName("ktime_t") Long> vblank_time,
      boolean in_vblank_irq,
      @OriginalName("drm_vblank_get_scanout_position_func") Ptr<?> get_scanout_position) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_vblank_off(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_vblank_on(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_crtc_vblank_on_config($arg1, (const struct drm_vblank_crtc_config *)$arg2)")
  public static void drm_crtc_vblank_on_config(Ptr<drm_crtc> crtc,
      Ptr<drm_vblank_crtc_config> config) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_vblank_put(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_vblank_reset(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_vblank_restore(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("wait_queue_head_t") wait_queue_head> drm_crtc_vblank_waitqueue(
      Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_crtc_wait_one_vblank(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_display_mode> drm_cvt_mode(Ptr<drm_device> dev, int hdisplay, int vdisplay,
      int vrefresh, boolean reduced, boolean interlaced, boolean margins) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_cvt_modes($arg1, (const struct detailed_timing *)$arg2)")
  public static int drm_cvt_modes(Ptr<drm_connector> connector, Ptr<detailed_timing> timing) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_debufs_proc_info_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_debugfs_add_file($arg1, (const u8 *)$arg2, (int (*)(struct seq_file*, void*))$arg3, $arg4)")
  public static void drm_debugfs_add_file(Ptr<drm_device> dev, String name, Ptr<?> show,
      Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_debugfs_add_files($arg1, (const struct drm_debugfs_info *)$arg2, $arg3)")
  public static void drm_debugfs_add_files(Ptr<drm_device> dev, Ptr<drm_debugfs_info> files,
      int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_bridge_params() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_clients_add(Ptr<drm_file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_clients_remove(Ptr<drm_file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_connector_add(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_connector_remove(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_debugfs_create_files((const struct drm_info_list *)$arg1, $arg2, $arg3, $arg4)")
  public static void drm_debugfs_create_files(Ptr<drm_info_list> files, int count, Ptr<dentry> root,
      Ptr<drm_minor> minor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_crtc_add(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_crtc_crc_add(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_crtc_remove(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_dev_fini(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_dev_init(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_dev_register(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_encoder_add(Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_encoder_remove(Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_debugfs_entry_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_debugfs_gpuva_info(Ptr<seq_file> m, Ptr<drm_gpuvm> gpuvm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_init_root() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_debugfs_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_debugfs_proc_info_show(Ptr<seq_file> m, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_debugfs_register(Ptr<drm_minor> minor, int minor_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_debugfs_remove_files((const struct drm_info_list *)$arg1, $arg2, $arg3, $arg4)")
  public static int drm_debugfs_remove_files(Ptr<drm_info_list> files, int count, Ptr<dentry> root,
      Ptr<drm_minor> minor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_remove_root() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_debugfs_unregister(Ptr<drm_minor> minor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_default_rgb_quant_range((const struct drm_display_mode *)$arg1)")
  public static hdmi_quantization_range drm_default_rgb_quant_range(Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_detect_hdmi_monitor((const struct edid *)$arg1)")
  public static boolean drm_detect_hdmi_monitor(Ptr<edid> edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_detect_monitor_audio((const struct edid *)$arg1)")
  public static boolean drm_detect_monitor_audio(Ptr<edid> edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_dev_alloc((const struct drm_driver *)$arg1, $arg2)")
  public static Ptr<drm_device> drm_dev_alloc(Ptr<drm_driver> driver, Ptr<device> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_dev_enter(Ptr<drm_device> dev, Ptr<java.lang.Integer> idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_dev_exit(int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_dev_get(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_dev_has_vblank((const struct drm_device *)$arg1)")
  public static boolean drm_dev_has_vblank(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_dev_init($arg1, (const struct drm_driver *)$arg2, $arg3)")
  public static int drm_dev_init(Ptr<drm_device> dev, Ptr<drm_driver> driver, Ptr<device> parent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_dev_init_release(Ptr<drm_device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_dev_needs_global_mutex(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_dev_printk((const struct device *)$arg1, (const u8 *)$arg2, (const u8 *)$arg3, $arg4_)")
  public static void drm_dev_printk(Ptr<device> dev, String level, String format,
      java.lang.Object... param3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_dev_put(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_dev_register(Ptr<drm_device> dev, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_dev_set_dma_dev(Ptr<drm_device> dev, Ptr<device> dma_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_dev_unplug(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_dev_unregister(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_dev_wedged_event(Ptr<drm_device> dev, @Unsigned long method,
      Ptr<drm_wedge_task_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_devnode((const struct device *)$arg1, $arg2)")
  public static String drm_devnode(Ptr<device> dev,
      Ptr<java.lang. @Unsigned @OriginalName("umode_t") Short> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_display_info_set_bus_formats($arg1, (const unsigned int *)$arg2, $arg3)")
  public static int drm_display_info_set_bus_formats(Ptr<drm_display_info> info,
      Ptr<java.lang. @Unsigned Integer> formats, @Unsigned int num_formats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_display_mode> drm_display_mode_from_cea_vic(Ptr<drm_device> dev,
      char video_code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_display_mode> drm_display_mode_from_vic_index(Ptr<drm_connector> connector,
      int vic_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_display_mode_from_videomode((const struct videomode *)$arg1, $arg2)")
  public static void drm_display_mode_from_videomode(Ptr<videomode> vm,
      Ptr<drm_display_mode> dmode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_display_mode_to_videomode((const struct drm_display_mode *)$arg1, $arg2)")
  public static void drm_display_mode_to_videomode(Ptr<drm_display_mode> dmode, Ptr<videomode> vm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_do_probe_ddc_edid(Ptr<?> data, Ptr<java.lang.Character> buf,
      @Unsigned int block, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_draw_blit16($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void drm_draw_blit16(Ptr<iosys_map> dmap, @Unsigned int dpitch,
      Ptr<java.lang.Character> sbuf8, @Unsigned int spitch, @Unsigned int height,
      @Unsigned int width, @Unsigned int scale, @Unsigned short fg16) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_draw_blit24($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void drm_draw_blit24(Ptr<iosys_map> dmap, @Unsigned int dpitch,
      Ptr<java.lang.Character> sbuf8, @Unsigned int spitch, @Unsigned int height,
      @Unsigned int width, @Unsigned int scale, @Unsigned int fg32) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_draw_blit32($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void drm_draw_blit32(Ptr<iosys_map> dmap, @Unsigned int dpitch,
      Ptr<java.lang.Character> sbuf8, @Unsigned int spitch, @Unsigned int height,
      @Unsigned int width, @Unsigned int scale, @Unsigned int fg32) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int drm_draw_color_from_xrgb8888(@Unsigned int color,
      @Unsigned int format) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_draw_fill16(Ptr<iosys_map> dmap, @Unsigned int dpitch,
      @Unsigned int height, @Unsigned int width, @Unsigned short color) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_draw_fill24(Ptr<iosys_map> dmap, @Unsigned int dpitch,
      @Unsigned int height, @Unsigned int width, @Unsigned int color) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_draw_fill32(Ptr<iosys_map> dmap, @Unsigned int dpitch,
      @Unsigned int height, @Unsigned int width, @Unsigned int color) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("uint32_t") int drm_driver_color_mode_format(
      Ptr<drm_device> dev, @Unsigned int color_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("uint32_t") int drm_driver_legacy_fb_format(
      Ptr<drm_device> dev, @Unsigned @OriginalName("uint32_t") int bpp,
      @Unsigned @OriginalName("uint32_t") int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_dropmaster_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_edid_alloc((const void *)$arg1, $arg2))")
  public static Ptr<drm_edid> drm_edid_alloc(Ptr<?> edid, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_edid_connector_add_modes(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long drm_edid_connector_property_show(
      Ptr<drm_connector> connector, String buf, @OriginalName("loff_t") long off,
      @Unsigned long count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_connector_update($arg1, (const struct drm_edid *)$arg2)")
  public static int drm_edid_connector_update(Ptr<drm_connector> connector,
      Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_cta_sad_get((const struct cea_sad *)$arg1, $arg2)")
  public static void drm_edid_cta_sad_get(Ptr<cea_sad> cta_sad, Ptr<java.lang.Character> sad) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_cta_sad_set($arg1, (const u8 *)$arg2)")
  public static void drm_edid_cta_sad_set(Ptr<cea_sad> cta_sad, Ptr<java.lang.Character> sad) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_edid_dup((const struct drm_edid *)$arg1))")
  public static Ptr<drm_edid> drm_edid_dup(Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_duplicate((const struct edid *)$arg1)")
  public static Ptr<edid> drm_edid_duplicate(Ptr<edid> edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_edid_find_extension((const struct drm_edid *)$arg1, $arg2, $arg3))")
  public static Ptr<java.lang.Character> drm_edid_find_extension(Ptr<drm_edid> drm_edid, int ext_id,
      Ptr<java.lang.Integer> ext_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_free((const struct drm_edid *)$arg1)")
  public static void drm_edid_free(Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_get_monitor_name((const struct edid *)$arg1, $arg2, $arg3)")
  public static void drm_edid_get_monitor_name(Ptr<edid> edid, String name, int bufsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_get_panel_id((const struct drm_edid *)$arg1)")
  public static @Unsigned int drm_edid_get_panel_id(Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_get_product_id((const struct drm_edid *)$arg1, $arg2)")
  public static void drm_edid_get_product_id(Ptr<drm_edid> drm_edid, Ptr<drm_edid_product_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_edid_has_quirk(Ptr<drm_connector> connector, drm_edid_quirk quirk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_header_is_valid((const void *)$arg1)")
  public static int drm_edid_header_is_valid(Ptr<?> _edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_is_digital((const struct drm_edid *)$arg1)")
  public static boolean drm_edid_is_digital(Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_edid_is_valid(Ptr<edid> edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_iter_begin((const struct drm_edid *)$arg1, $arg2)")
  public static void drm_edid_iter_begin(Ptr<drm_edid> drm_edid, Ptr<drm_edid_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_edid_iter_end(Ptr<drm_edid_iter> iter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_edid_legacy_init($arg1, (const struct edid *)$arg2))")
  public static Ptr<drm_edid> drm_edid_legacy_init(Ptr<drm_edid> drm_edid, Ptr<edid> edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_edid_load_firmware($arg1))")
  public static Ptr<drm_edid> drm_edid_load_firmware(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_match((const struct drm_edid *)$arg1, (const struct drm_edid_ident *)$arg2)")
  public static boolean drm_edid_match(Ptr<drm_edid> drm_edid, Ptr<drm_edid_ident> ident) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_edid_override_connector_update(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_edid_override_get($arg1))")
  public static Ptr<drm_edid> drm_edid_override_get(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_edid_override_reset(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_override_set($arg1, (const void *)$arg2, $arg3)")
  public static int drm_edid_override_set(Ptr<drm_connector> connector, Ptr<?> edid,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_edid_override_show(Ptr<drm_connector> connector, Ptr<seq_file> m) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_print_product_id($arg1, (const struct drm_edid_product_id *)$arg2, $arg3)")
  public static void drm_edid_print_product_id(Ptr<drm_printer> p, Ptr<drm_edid_product_id> id,
      boolean raw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct edid*)drm_edid_raw((const struct drm_edid *)$arg1))")
  public static Ptr<edid> drm_edid_raw(Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_edid_read($arg1))")
  public static Ptr<drm_edid> drm_edid_read(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_edid_read_base_block($arg1))")
  public static Ptr<drm_edid> drm_edid_read_base_block(Ptr<i2c_adapter> adapter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_edid_read_custom($arg1, $arg2, $arg3))")
  public static Ptr<drm_edid> drm_edid_read_custom(Ptr<drm_connector> connector, Ptr<?> read_block,
      Ptr<?> context) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_edid_read_ddc($arg1, $arg2))")
  public static Ptr<drm_edid> drm_edid_read_ddc(Ptr<drm_connector> connector,
      Ptr<i2c_adapter> adapter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_edid*)drm_edid_read_switcheroo($arg1, $arg2))")
  public static Ptr<drm_edid> drm_edid_read_switcheroo(Ptr<drm_connector> connector,
      Ptr<i2c_adapter> adapter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_to_eld($arg1, (const struct drm_edid *)$arg2)")
  public static void drm_edid_to_eld(Ptr<drm_connector> connector, Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_to_sad((const struct edid *)$arg1, $arg2)")
  public static int drm_edid_to_sad(Ptr<edid> edid, Ptr<Ptr<cea_sad>> sads) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_to_speaker_allocation((const struct edid *)$arg1, $arg2)")
  public static int drm_edid_to_speaker_allocation(Ptr<edid> edid,
      Ptr<Ptr<java.lang.Character>> sadb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_edid_valid((const struct drm_edid *)$arg1)")
  public static boolean drm_edid_valid(Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_eld_sad_get((const u8 *)$arg1, $arg2, $arg3)")
  public static int drm_eld_sad_get(Ptr<java.lang.Character> eld, int sad_index,
      Ptr<cea_sad> cta_sad) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_eld_sad_set($arg1, $arg2, (const struct cea_sad *)$arg3)")
  public static int drm_eld_sad_set(Ptr<java.lang.Character> eld, int sad_index,
      Ptr<cea_sad> cta_sad) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_encoder_cleanup(Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_encoder_disable(Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_encoder_init($arg1, $arg2, (const struct drm_encoder_funcs *)$arg3, $arg4, (const u8 *)$arg5, $arg6_)")
  public static int drm_encoder_init(Ptr<drm_device> dev, Ptr<drm_encoder> encoder,
      Ptr<drm_encoder_funcs> funcs, int encoder_type, String name, java.lang.Object... param5) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_encoder_mode_valid($arg1, (const struct drm_display_mode *)$arg2)")
  public static drm_mode_status drm_encoder_mode_valid(Ptr<drm_encoder> encoder,
      Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_encoder_register_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_encoder_unregister_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_event_cancel_free(Ptr<drm_device> dev, Ptr<drm_pending_event> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_event_reserve_init(Ptr<drm_device> dev, Ptr<drm_file> file_priv,
      Ptr<drm_pending_event> p, Ptr<drm_event> e) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_event_reserve_init_locked(Ptr<drm_device> dev, Ptr<drm_file> file_priv,
      Ptr<drm_pending_event> p, Ptr<drm_event> e) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_argb8888_to_argb4444($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_argb8888_to_argb4444(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_argb8888_to_argb4444_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_argb8888_to_argb4444_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_blit($arg1, (const unsigned int *)$arg2, $arg3, (const struct iosys_map *)$arg4, (const struct drm_framebuffer *)$arg5, (const struct drm_rect *)$arg6, $arg7)")
  public static int drm_fb_blit(Ptr<iosys_map> dst, Ptr<java.lang. @Unsigned Integer> dst_pitch,
      @Unsigned @OriginalName("uint32_t") int dst_format, Ptr<iosys_map> src,
      Ptr<drm_framebuffer> fb, Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_clip_offset($arg1, (const struct drm_format_info *)$arg2, (const struct drm_rect *)$arg3)")
  public static @Unsigned int drm_fb_clip_offset(@Unsigned int pitch, Ptr<drm_format_info> format,
      Ptr<drm_rect> clip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<fb_info> drm_fb_helper_alloc_info(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_blank(int blank, Ptr<fb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_check_var(Ptr<fb_var_screeninfo> var, Ptr<fb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_damage_area(Ptr<fb_info> info, @Unsigned int x, @Unsigned int y,
      @Unsigned int width, @Unsigned int height) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_damage_range(Ptr<fb_info> info, @OriginalName("off_t") long off,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_damage_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_debug_enter(Ptr<fb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_debug_leave(Ptr<fb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_deferred_io(Ptr<fb_info> info, Ptr<list_head> pagereflist) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_fill_info(Ptr<fb_info> info, Ptr<drm_fb_helper> fb_helper,
      Ptr<drm_fb_helper_surface_size> sizes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_helper_fill_pixel_fmt($arg1, (const struct drm_format_info *)$arg2)")
  public static void drm_fb_helper_fill_pixel_fmt(Ptr<fb_var_screeninfo> var,
      Ptr<drm_format_info> format) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_fini(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_hotplug_event(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_init(Ptr<drm_device> dev, Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_initial_config(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_ioctl(Ptr<fb_info> info, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_lastclose(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_pan_display(Ptr<fb_var_screeninfo> var, Ptr<fb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_helper_prepare($arg1, $arg2, $arg3, (const struct drm_fb_helper_funcs *)$arg4)")
  public static void drm_fb_helper_prepare(Ptr<drm_device> dev, Ptr<drm_fb_helper> helper,
      @Unsigned int preferred_bpp, Ptr<drm_fb_helper_funcs> funcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_release_info(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_restore_fbdev_mode_unlocked(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_restore_work_fn(Ptr<work_struct> ignored) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_resume_worker(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_set_par(Ptr<fb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_set_suspend(Ptr<drm_fb_helper> fb_helper, boolean suspend) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_set_suspend_unlocked(Ptr<drm_fb_helper> fb_helper,
      boolean suspend) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_setcmap(Ptr<fb_cmap> cmap, Ptr<fb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fb_helper_single_fb_probe(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_sysrq(char dummy1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_unprepare(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_helper_unregister_info(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_memcpy($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5)")
  public static void drm_fb_memcpy(Ptr<iosys_map> dst, Ptr<java.lang. @Unsigned Integer> dst_pitch,
      Ptr<iosys_map> src, Ptr<drm_framebuffer> fb, Ptr<drm_rect> clip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fb_release(Ptr<drm_file> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_swab($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6, $arg7)")
  public static void drm_fb_swab(Ptr<iosys_map> dst, Ptr<java.lang. @Unsigned Integer> dst_pitch,
      Ptr<iosys_map> src, Ptr<drm_framebuffer> fb, Ptr<drm_rect> clip, boolean cached,
      Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_swab16_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_swab16_line(Ptr<?> dbuf, Ptr<?> sbuf, @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_swab32_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_swab32_line(Ptr<?> dbuf, Ptr<?> sbuf, @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xfrm($arg1, (const unsigned int *)$arg2, (const u8 *)$arg3, (const struct iosys_map *)$arg4, (const struct drm_framebuffer *)$arg5, (const struct drm_rect *)$arg6, $arg7, $arg8, (void (*)(void*, const void*, unsigned int))$arg9)")
  public static int drm_fb_xfrm(Ptr<iosys_map> dst, Ptr<java.lang. @Unsigned Integer> dst_pitch,
      Ptr<java.lang.Character> dst_pixsize, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, boolean vaddr_cached_hint, Ptr<drm_format_conv_state> state,
      Ptr<?> xfrm_line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_abgr8888($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_abgr8888(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_abgr8888_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_abgr8888_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_argb1555($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_argb1555(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_argb1555_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_argb1555_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_argb2101010($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_argb2101010(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_argb2101010_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_argb2101010_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_argb8888($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_argb8888(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_argb8888_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_argb8888_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_bgr888($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_bgr888(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_bgr888_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_bgr888_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_bgrx8888($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_bgrx8888(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_bgrx8888_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_bgrx8888_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_gray8($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_gray8(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_gray8_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_gray8_line(Ptr<?> dbuf, Ptr<?> sbuf, @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_mono($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_mono(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_rgb332($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_rgb332(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_rgb332_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_rgb332_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_rgb565($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_rgb565(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_rgb565_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_rgb565_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_rgb565be($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_rgb565be(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_rgb565be_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_rgb565be_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_rgb888($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_rgb888(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_rgb888_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_rgb888_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_rgba5551($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_rgba5551(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_rgba5551_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_rgba5551_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_xbgr8888($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_xbgr8888(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_xbgr8888_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_xbgr8888_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_xrgb1555($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_xrgb1555(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_xrgb1555_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_xrgb1555_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_xrgb2101010($arg1, (const unsigned int *)$arg2, (const struct iosys_map *)$arg3, (const struct drm_framebuffer *)$arg4, (const struct drm_rect *)$arg5, $arg6)")
  public static void drm_fb_xrgb8888_to_xrgb2101010(Ptr<iosys_map> dst,
      Ptr<java.lang. @Unsigned Integer> dst_pitch, Ptr<iosys_map> src, Ptr<drm_framebuffer> fb,
      Ptr<drm_rect> clip, Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fb_xrgb8888_to_xrgb2101010_line($arg1, (const void *)$arg2, $arg3)")
  public static void drm_fb_xrgb8888_to_xrgb2101010_line(Ptr<?> dbuf, Ptr<?> sbuf,
      @Unsigned int pixels) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fbdev_client_hotplug(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fbdev_client_restore(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fbdev_client_resume(Ptr<drm_client_dev> client,
      boolean holds_console_lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fbdev_client_setup($arg1, (const struct drm_format_info *)$arg2)")
  public static int drm_fbdev_client_setup(Ptr<drm_device> dev, Ptr<drm_format_info> format) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fbdev_client_suspend(Ptr<drm_client_dev> client,
      boolean holds_console_lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fbdev_client_unregister(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fbdev_shmem_defio_copyarea($arg1, (const struct fb_copyarea *)$arg2)")
  public static void drm_fbdev_shmem_defio_copyarea(Ptr<fb_info> info, Ptr<fb_copyarea> area) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fbdev_shmem_defio_fillrect($arg1, (const struct fb_fillrect *)$arg2)")
  public static void drm_fbdev_shmem_defio_fillrect(Ptr<fb_info> info, Ptr<fb_fillrect> rect) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fbdev_shmem_defio_imageblit($arg1, (const struct fb_image *)$arg2)")
  public static void drm_fbdev_shmem_defio_imageblit(Ptr<fb_info> info, Ptr<fb_image> image) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long drm_fbdev_shmem_defio_read(Ptr<fb_info> info,
      String buf, @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fbdev_shmem_defio_write($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long drm_fbdev_shmem_defio_write(Ptr<fb_info> info,
      String buf, @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fbdev_shmem_driver_fbdev_probe(Ptr<drm_fb_helper> fb_helper,
      Ptr<drm_fb_helper_surface_size> sizes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_fbdev_shmem_fb_destroy(Ptr<fb_info> info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fbdev_shmem_fb_mmap(Ptr<fb_info> info, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fbdev_shmem_fb_open(Ptr<fb_info> info, int user) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fbdev_shmem_fb_release(Ptr<fb_info> info, int user) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<page> drm_fbdev_shmem_get_page(Ptr<fb_info> info, @Unsigned long offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fbdev_shmem_helper_fb_dirty(Ptr<drm_fb_helper> helper,
      Ptr<drm_clip_rect> clip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_fdinfo_print_size($arg1, (const u8 *)$arg2, (const u8 *)$arg3, (const u8 *)$arg4, $arg5)")
  public static void drm_fdinfo_print_size(Ptr<drm_printer> p, String prefix, String stat,
      String region, @Unsigned long sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_file> drm_file_alloc(Ptr<drm_minor> minor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_file_err($arg1, (const u8 *)$arg2, $arg3_)")
  public static void drm_file_err(Ptr<drm_file> file_priv, String fmt, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_file_free(Ptr<drm_file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_master> drm_file_get_master(Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_file_update_pid(Ptr<drm_file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_flip_work_cleanup(Ptr<drm_flip_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_flip_work_commit(Ptr<drm_flip_work> work, Ptr<workqueue_struct> wq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_flip_work_init($arg1, (const u8 *)$arg2, $arg3)")
  public static void drm_flip_work_init(Ptr<drm_flip_work> work, String name,
      @OriginalName("drm_flip_func_t") Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_flip_work_queue(Ptr<drm_flip_work> work, Ptr<?> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_for_each_detailed_block((const struct drm_edid *)$arg1, $arg2, $arg3)")
  public static void drm_for_each_detailed_block(Ptr<drm_edid> drm_edid, Ptr<?> cb,
      Ptr<?> closure) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_format_conv_state_copy($arg1, (const struct drm_format_conv_state *)$arg2)")
  public static void drm_format_conv_state_copy(Ptr<drm_format_conv_state> state,
      Ptr<drm_format_conv_state> old_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_format_conv_state_init(Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_format_conv_state_release(Ptr<drm_format_conv_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> drm_format_conv_state_reserve(Ptr<drm_format_conv_state> state,
      @Unsigned long new_size, @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_format_info_block_height((const struct drm_format_info *)$arg1, $arg2)")
  public static @Unsigned int drm_format_info_block_height(Ptr<drm_format_info> info, int plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_format_info_block_width((const struct drm_format_info *)$arg1, $arg2)")
  public static @Unsigned int drm_format_info_block_width(Ptr<drm_format_info> info, int plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_format_info_bpp((const struct drm_format_info *)$arg1, $arg2)")
  public static @Unsigned int drm_format_info_bpp(Ptr<drm_format_info> info, int plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_format_info_min_pitch((const struct drm_format_info *)$arg1, $arg2, $arg3)")
  public static @Unsigned @OriginalName("uint64_t") long drm_format_info_min_pitch(
      Ptr<drm_format_info> info, int plane, @Unsigned int buffer_width) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_framebuffer_check_src_coords($arg1, $arg2, $arg3, $arg4, (const struct drm_framebuffer *)$arg5)")
  public static int drm_framebuffer_check_src_coords(@Unsigned @OriginalName("uint32_t") int src_x,
      @Unsigned @OriginalName("uint32_t") int src_y, @Unsigned @OriginalName("uint32_t") int src_w,
      @Unsigned @OriginalName("uint32_t") int src_h, Ptr<drm_framebuffer> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_framebuffer_cleanup(Ptr<drm_framebuffer> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_framebuffer_debugfs_init(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_framebuffer_free(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_framebuffer_info(Ptr<seq_file> m, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_framebuffer_init($arg1, $arg2, (const struct drm_framebuffer_funcs *)$arg3)")
  public static int drm_framebuffer_init(Ptr<drm_device> dev, Ptr<drm_framebuffer> fb,
      Ptr<drm_framebuffer_funcs> funcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_framebuffer> drm_framebuffer_lookup(Ptr<drm_device> dev,
      Ptr<drm_file> file_priv, @Unsigned @OriginalName("uint32_t") int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_framebuffer_print_info($arg1, $arg2, (const struct drm_framebuffer *)$arg3)")
  public static void drm_framebuffer_print_info(Ptr<drm_printer> p, @Unsigned int indent,
      Ptr<drm_framebuffer> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_framebuffer_remove(Ptr<drm_framebuffer> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_framebuffer_unregister_private(Ptr<drm_framebuffer> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_fs_init_fs_context(Ptr<fs_context> fc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_begin_shadow_fb_access(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_close_ioctl(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_create_mmap_offset(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_create_mmap_offset_size(Ptr<drm_gem_object> obj, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_destroy_shadow_plane_state(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long drm_gem_dma_resv_wait(Ptr<drm_file> filep, @Unsigned int handle,
      boolean wait_all, @Unsigned long timeout) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_buf> drm_gem_dmabuf_export(Ptr<drm_device> dev,
      Ptr<dma_buf_export_info> exp_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_dmabuf_mmap(Ptr<dma_buf> dma_buf, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_dmabuf_release(Ptr<dma_buf> dma_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_dmabuf_vmap(Ptr<dma_buf> dma_buf, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_dmabuf_vunmap(Ptr<dma_buf> dma_buf, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_dumb_map_offset(Ptr<drm_file> file, Ptr<drm_device> dev,
      @Unsigned int handle, Ptr<java.lang. @Unsigned Long> offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_plane_state> drm_gem_duplicate_shadow_plane_state(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_end_shadow_fb_access(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_evict_locked(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_gem_fb_afbc_init($arg1, (const struct drm_format_info *)$arg2, (const struct drm_mode_fb_cmd2 *)$arg3, $arg4)")
  public static int drm_gem_fb_afbc_init(Ptr<drm_device> dev, Ptr<drm_format_info> info,
      Ptr<drm_mode_fb_cmd2> mode_cmd, Ptr<drm_afbc_framebuffer> afbc_fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_fb_begin_cpu_access(Ptr<drm_framebuffer> fb, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_gem_fb_create($arg1, $arg2, (const struct drm_format_info *)$arg3, (const struct drm_mode_fb_cmd2 *)$arg4)")
  public static Ptr<drm_framebuffer> drm_gem_fb_create(Ptr<drm_device> dev, Ptr<drm_file> file,
      Ptr<drm_format_info> info, Ptr<drm_mode_fb_cmd2> mode_cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_fb_create_handle(Ptr<drm_framebuffer> fb, Ptr<drm_file> file,
      Ptr<java.lang. @Unsigned Integer> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_gem_fb_create_with_dirty($arg1, $arg2, (const struct drm_format_info *)$arg3, (const struct drm_mode_fb_cmd2 *)$arg4)")
  public static Ptr<drm_framebuffer> drm_gem_fb_create_with_dirty(Ptr<drm_device> dev,
      Ptr<drm_file> file, Ptr<drm_format_info> info, Ptr<drm_mode_fb_cmd2> mode_cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_gem_fb_create_with_funcs($arg1, $arg2, (const struct drm_format_info *)$arg3, (const struct drm_mode_fb_cmd2 *)$arg4, (const struct drm_framebuffer_funcs *)$arg5)")
  public static Ptr<drm_framebuffer> drm_gem_fb_create_with_funcs(Ptr<drm_device> dev,
      Ptr<drm_file> file, Ptr<drm_format_info> info, Ptr<drm_mode_fb_cmd2> mode_cmd,
      Ptr<drm_framebuffer_funcs> funcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_fb_destroy(Ptr<drm_framebuffer> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_fb_end_cpu_access(Ptr<drm_framebuffer> fb, dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_gem_object> drm_gem_fb_get_obj(Ptr<drm_framebuffer> fb,
      @Unsigned int plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_gem_fb_init_with_funcs($arg1, $arg2, $arg3, (const struct drm_format_info *)$arg4, (const struct drm_mode_fb_cmd2 *)$arg5, (const struct drm_framebuffer_funcs *)$arg6)")
  public static int drm_gem_fb_init_with_funcs(Ptr<drm_device> dev, Ptr<drm_framebuffer> fb,
      Ptr<drm_file> file, Ptr<drm_format_info> info, Ptr<drm_mode_fb_cmd2> mode_cmd,
      Ptr<drm_framebuffer_funcs> funcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_fb_vmap(Ptr<drm_framebuffer> fb, Ptr<iosys_map> map,
      Ptr<iosys_map> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_fb_vunmap(Ptr<drm_framebuffer> fb, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_flink_ioctl(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_free_mmap_offset(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<Ptr<page>> drm_gem_get_pages(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_handle_create(Ptr<drm_file> file_priv, Ptr<drm_gem_object> obj,
      Ptr<java.lang. @Unsigned Integer> handlep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_handle_create_tail(Ptr<drm_file> file_priv, Ptr<drm_gem_object> obj,
      Ptr<java.lang. @Unsigned Integer> handlep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_handle_delete(Ptr<drm_file> filp, @Unsigned int handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_init(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_init_release(Ptr<drm_device> dev, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_gem_is_prime_exported_dma_buf(Ptr<drm_device> dev,
      Ptr<dma_buf> dma_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_lock(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_lock_reservations(Ptr<Ptr<drm_gem_object>> objs, int count,
      Ptr<ww_acquire_ctx> acquire_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_lru_init(Ptr<drm_gem_lru> lru, Ptr<mutex> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_lru_move_tail(Ptr<drm_gem_lru> lru, Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_lru_move_tail_locked(Ptr<drm_gem_lru> lru, Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_lru_remove(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_gem_lru_scan($arg1, $arg2, $arg3, (_Bool (*)(struct drm_gem_object*, struct ww_acquire_ctx*))$arg4, $arg5)")
  public static @Unsigned long drm_gem_lru_scan(Ptr<drm_gem_lru> lru, @Unsigned int nr_to_scan,
      Ptr<java.lang. @Unsigned Long> remaining, Ptr<?> shrink, Ptr<ww_acquire_ctx> ticket) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_map_attach(Ptr<dma_buf> dma_buf, Ptr<dma_buf_attachment> attach) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_map_detach(Ptr<dma_buf> dma_buf, Ptr<dma_buf_attachment> attach) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> drm_gem_map_dma_buf(Ptr<dma_buf_attachment> attach,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_mmap(Ptr<file> filp, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_mmap_obj(Ptr<drm_gem_object> obj, @Unsigned long obj_size,
      Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_name_info(Ptr<seq_file> m, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_object_free(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_object_handle_get(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_gem_object_handle_get_if_exists_unlocked(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_object_handle_put_unlocked(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_object_init(Ptr<drm_device> dev, Ptr<drm_gem_object> obj,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_object_init_with_mnt(Ptr<drm_device> dev, Ptr<drm_gem_object> obj,
      @Unsigned long size, Ptr<vfsmount> gemfs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_gem_object> drm_gem_object_lookup(Ptr<drm_file> filp,
      @Unsigned int handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_object_release(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_object_release_handle(int id, Ptr<?> ptr, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_objects_lookup(Ptr<drm_file> filp, Ptr<?> bo_handles, int count,
      Ptr<Ptr<Ptr<drm_gem_object>>> objs_out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_one_name_info(int id, Ptr<?> ptr, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_open_ioctl(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_plane_helper_prepare_fb(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_buf> drm_gem_prime_export(Ptr<drm_gem_object> obj, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_prime_fd_to_handle(Ptr<drm_device> dev, Ptr<drm_file> file_priv,
      int prime_fd, Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_buf> drm_gem_prime_handle_to_dmabuf(Ptr<drm_device> dev,
      Ptr<drm_file> file_priv, @Unsigned @OriginalName("uint32_t") int handle,
      @Unsigned @OriginalName("uint32_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_prime_handle_to_fd(Ptr<drm_device> dev, Ptr<drm_file> file_priv,
      @Unsigned @OriginalName("uint32_t") int handle, @Unsigned @OriginalName("uint32_t") int flags,
      Ptr<java.lang.Integer> prime_fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_gem_object> drm_gem_prime_import(Ptr<drm_device> dev,
      Ptr<dma_buf> dma_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_gem_object> drm_gem_prime_import_dev(Ptr<drm_device> dev,
      Ptr<dma_buf> dma_buf, Ptr<device> attach_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_prime_mmap(Ptr<drm_gem_object> obj, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_gem_print_info($arg1, $arg2, (const struct drm_gem_object *)$arg3)")
  public static void drm_gem_print_info(Ptr<drm_printer> p, @Unsigned int indent,
      Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_private_object_fini(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_private_object_init(Ptr<drm_device> dev, Ptr<drm_gem_object> obj,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_put_pages(Ptr<drm_gem_object> obj, Ptr<Ptr<page>> pages, boolean dirty,
      boolean accessed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_release(Ptr<drm_device> dev, Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_reset_shadow_plane(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_gem_shmem_object> drm_gem_shmem_create(Ptr<drm_device> dev,
      @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_gem_shmem_object> drm_gem_shmem_create_with_mnt(Ptr<drm_device> dev,
      @Unsigned long size, Ptr<vfsmount> gemfs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_shmem_dumb_create(Ptr<drm_file> file, Ptr<drm_device> dev,
      Ptr<drm_mode_create_dumb> args) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("vm_fault_t") int drm_gem_shmem_fault(Ptr<vm_fault> vmf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_free(Ptr<drm_gem_shmem_object> shmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_shmem_get_pages_locked(Ptr<drm_gem_shmem_object> shmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> drm_gem_shmem_get_pages_sgt(Ptr<drm_gem_shmem_object> shmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> drm_gem_shmem_get_sg_table(Ptr<drm_gem_shmem_object> shmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_shmem_madvise_locked(Ptr<drm_gem_shmem_object> shmem, int madv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_shmem_mmap(Ptr<drm_gem_shmem_object> shmem, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_object_free(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> drm_gem_shmem_object_get_sg_table(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_shmem_object_mmap(Ptr<drm_gem_object> obj, Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_shmem_object_pin(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_gem_shmem_object_print_info($arg1, $arg2, (const struct drm_gem_object *)$arg3)")
  public static void drm_gem_shmem_object_print_info(Ptr<drm_printer> p, @Unsigned int indent,
      Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_object_unpin(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_shmem_object_vmap(Ptr<drm_gem_object> obj, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_object_vunmap(Ptr<drm_gem_object> obj, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_shmem_pin(Ptr<drm_gem_shmem_object> shmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_shmem_pin_locked(Ptr<drm_gem_shmem_object> shmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_gem_object> drm_gem_shmem_prime_import_no_map(Ptr<drm_device> dev,
      Ptr<dma_buf> dma_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_gem_object> drm_gem_shmem_prime_import_sg_table(Ptr<drm_device> dev,
      Ptr<dma_buf_attachment> attach, Ptr<sg_table> sgt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_gem_shmem_print_info((const struct drm_gem_shmem_object *)$arg1, $arg2, $arg3)")
  public static void drm_gem_shmem_print_info(Ptr<drm_gem_shmem_object> shmem, Ptr<drm_printer> p,
      @Unsigned int indent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_purge_locked(Ptr<drm_gem_shmem_object> shmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_put_pages_locked(Ptr<drm_gem_shmem_object> shmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_unpin(Ptr<drm_gem_shmem_object> shmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_unpin_locked(Ptr<drm_gem_shmem_object> shmem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_vm_close(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_vm_open(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_shmem_vmap_locked(Ptr<drm_gem_shmem_object> shmem, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_shmem_vunmap_locked(Ptr<drm_gem_shmem_object> shmem,
      Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_simple_kms_begin_shadow_fb_access(Ptr<drm_simple_display_pipe> pipe,
      Ptr<drm_plane_state> plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_simple_kms_destroy_shadow_plane_state(
      Ptr<drm_simple_display_pipe> pipe, Ptr<drm_plane_state> plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_plane_state> drm_gem_simple_kms_duplicate_shadow_plane_state(
      Ptr<drm_simple_display_pipe> pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_simple_kms_end_shadow_fb_access(Ptr<drm_simple_display_pipe> pipe,
      Ptr<drm_plane_state> plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_simple_kms_reset_shadow_plane(Ptr<drm_simple_display_pipe> pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_unlock(Ptr<drm_gem_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_unlock_reservations(Ptr<Ptr<drm_gem_object>> objs, int count,
      Ptr<ww_acquire_ctx> acquire_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_unmap_dma_buf(Ptr<dma_buf_attachment> attach, Ptr<sg_table> sgt,
      dma_data_direction dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_vm_close(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_vm_open(Ptr<vm_area_struct> vma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_vmap(Ptr<drm_gem_object> obj, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_gem_vmap_locked(Ptr<drm_gem_object> obj, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_vunmap(Ptr<drm_gem_object> obj, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_gem_vunmap_locked(Ptr<drm_gem_object> obj, Ptr<iosys_map> map) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_color_encoding_name($arg1))")
  public static String drm_get_color_encoding_name(drm_color_encoding encoding) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_color_range_name($arg1))")
  public static String drm_get_color_range_name(drm_color_range range) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_colorspace_name($arg1))")
  public static String drm_get_colorspace_name(drm_colorspace colorspace) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_connector_force_name($arg1))")
  public static String drm_get_connector_force_name(drm_connector_force force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_connector_status_name($arg1))")
  public static String drm_get_connector_status_name(drm_connector_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_connector_type_name($arg1))")
  public static String drm_get_connector_type_name(@Unsigned int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_dp_subconnector_name($arg1))")
  public static String drm_get_dp_subconnector_name(int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_dpms_name($arg1))")
  public static String drm_get_dpms_name(int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_dvi_i_select_name($arg1))")
  public static String drm_get_dvi_i_select_name(int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_dvi_i_subconnector_name($arg1))")
  public static String drm_get_dvi_i_subconnector_name(int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<edid> drm_get_edid(Ptr<drm_connector> connector, Ptr<i2c_adapter> adapter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<edid> drm_get_edid_switcheroo(Ptr<drm_connector> connector,
      Ptr<i2c_adapter> adapter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_format_info*)drm_get_format_info($arg1, $arg2, $arg3))")
  public static Ptr<drm_format_info> drm_get_format_info(Ptr<drm_device> dev,
      @Unsigned int pixel_format, @Unsigned long modifier) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_get_max_frl_rate(int max_frl_rate, Ptr<java.lang.Character> max_lanes,
      Ptr<java.lang.Character> max_rate_per_lane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_mode_status_name($arg1))")
  public static String drm_get_mode_status_name(drm_mode_status status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_get_panel_orientation_quirk(int width, int height) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_subpixel_order_name($arg1))")
  public static String drm_get_subpixel_order_name(subpixel_order order) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_get_tv_mode_from_name((const u8 *)$arg1, $arg2)")
  public static int drm_get_tv_mode_from_name(String name, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_tv_mode_name($arg1))")
  public static String drm_get_tv_mode_name(int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_tv_select_name($arg1))")
  public static String drm_get_tv_select_name(int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_get_tv_subconnector_name($arg1))")
  public static String drm_get_tv_subconnector_name(int val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_getcap(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_getclient(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_getmagic(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_getstats(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_getunique(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_gtf2_mode($arg1, (const struct drm_edid *)$arg2, $arg3, $arg4, $arg5)")
  public static Ptr<drm_display_mode> drm_gtf2_mode(Ptr<drm_device> dev, Ptr<drm_edid> drm_edid,
      int hsize, int vsize, int vrefresh_rate) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_display_mode> drm_gtf_mode(Ptr<drm_device> dev, int hdisplay, int vdisplay,
      int vrefresh, boolean interlaced, int margins) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_display_mode> drm_gtf_mode_complex(Ptr<drm_device> dev, int hdisplay,
      int vdisplay, int vrefresh, boolean interlaced, int margins, int GTF_M, int GTF_2C, int GTF_K,
      int GTF_2J) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_handle_vblank(Ptr<drm_device> dev, @Unsigned int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_handle_vblank_events(Ptr<drm_device> dev, @Unsigned int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_handle_vblank_works(Ptr<drm_vblank_crtc> vblank) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_hdmi_avi_infoframe_from_display_mode($arg1, (const struct drm_connector *)$arg2, (const struct drm_display_mode *)$arg3)")
  public static int drm_hdmi_avi_infoframe_from_display_mode(Ptr<hdmi_avi_infoframe> frame,
      Ptr<drm_connector> connector, Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_hdmi_avi_infoframe_quant_range($arg1, (const struct drm_connector *)$arg2, (const struct drm_display_mode *)$arg3, $arg4)")
  public static void drm_hdmi_avi_infoframe_quant_range(Ptr<hdmi_avi_infoframe> frame,
      Ptr<drm_connector> connector, Ptr<drm_display_mode> mode,
      hdmi_quantization_range rgb_quant_range) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_hdmi_connector_get_broadcast_rgb_name($arg1))")
  public static String drm_hdmi_connector_get_broadcast_rgb_name(
      drm_hdmi_broadcast_rgb broadcast_rgb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_hdmi_connector_get_output_format_name($arg1))")
  public static String drm_hdmi_connector_get_output_format_name(hdmi_colorspace fmt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_hdmi_vendor_infoframe_from_display_mode($arg1, (const struct drm_connector *)$arg2, (const struct drm_display_mode *)$arg3)")
  public static int drm_hdmi_vendor_infoframe_from_display_mode(Ptr<hdmi_vendor_infoframe> frame,
      Ptr<drm_connector> connector, Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_helper_choose_crtc_dpms(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_helper_connector_dpms(Ptr<drm_connector> connector, int mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_helper_crtc_in_use(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_helper_disable_unused_functions(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_helper_encoder_in_use(Ptr<drm_encoder> encoder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_helper_force_disable_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_helper_hpd_irq_event(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_helper_mode_fill_fb_struct($arg1, $arg2, (const struct drm_format_info *)$arg3, (const struct drm_mode_fb_cmd2 *)$arg4)")
  public static void drm_helper_mode_fill_fb_struct(Ptr<drm_device> dev, Ptr<drm_framebuffer> fb,
      Ptr<drm_format_info> info, Ptr<drm_mode_fb_cmd2> mode_cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_helper_move_panel_connectors_to_head(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_helper_probe_detect(Ptr<drm_connector> connector,
      Ptr<drm_modeset_acquire_ctx> ctx, boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static drm_connector_status drm_helper_probe_detect_ctx(Ptr<drm_connector> connector,
      boolean force) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_helper_probe_single_connector_modes(Ptr<drm_connector> connector,
      @Unsigned @OriginalName("uint32_t") int maxX, @Unsigned @OriginalName("uint32_t") int maxY) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_helper_resume_force_mode(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_internal_framebuffer_create($arg1, (const struct drm_mode_fb_cmd2 *)$arg2, $arg3)")
  public static Ptr<drm_framebuffer> drm_internal_framebuffer_create(Ptr<drm_device> dev,
      Ptr<drm_mode_fb_cmd2> r, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_invalid_op(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long drm_ioctl(Ptr<file> filp, @Unsigned int cmd, @Unsigned long arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long drm_ioctl_kernel(Ptr<file> file, Ptr<?> func, Ptr<?> kdata,
      @Unsigned int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_is_current_master(Ptr<drm_file> fpriv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_is_panel_follower(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_kms_helper_connector_hotplug_event(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_kms_helper_disable_hpd(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_kms_helper_hotplug_event(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_kms_helper_is_poll_worker() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_kms_helper_poll_disable(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_kms_helper_poll_enable(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_kms_helper_poll_fini(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_kms_helper_poll_init(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_kms_helper_poll_init_release(Ptr<drm_device> dev, Ptr<?> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_kms_helper_poll_reschedule(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_master> drm_lease_create(Ptr<drm_master> lessor, Ptr<idr> leases) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_lease_destroy(Ptr<drm_master> master) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("uint32_t") int drm_lease_filter_crtcs(
      Ptr<drm_file> file_priv, @Unsigned @OriginalName("uint32_t") int crtcs_in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_lease_held(Ptr<drm_file> file_priv, int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_master> drm_lease_owner(Ptr<drm_master> master) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_lease_revoke(Ptr<drm_master> top) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_log_clear_line(Ptr<drm_log_scanout> scanout, @Unsigned int line) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_log_client_hotplug(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_log_client_resume(Ptr<drm_client_dev> client, boolean _console_lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_log_client_suspend(Ptr<drm_client_dev> client, boolean _console_lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_log_client_unregister(Ptr<drm_client_dev> client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_log_draw_line($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void drm_log_draw_line(Ptr<drm_log_scanout> scanout, String s, @Unsigned int len,
      @Unsigned int prefix_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_log_draw_new_line($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static void drm_log_draw_new_line(Ptr<drm_log_scanout> scanout, String s,
      @Unsigned int len, @Unsigned int prefix_len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_log_init_client(Ptr<drm_log> dlog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_log_lock(Ptr<console> con, Ptr<java.lang. @Unsigned Long> flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_log_register(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_log_unlock(Ptr<console> con, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_log_write_thread(Ptr<console> con, Ptr<nbcon_write_context> wctxt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_managed_release(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_master> drm_master_create(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_master_destroy(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_master> drm_master_get(Ptr<drm_master> master) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_master_internal_acquire(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_master_internal_release(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_master_open(Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_master_put(Ptr<Ptr<drm_master>> master) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_master_release(Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_match_cea_mode((const struct drm_display_mode *)$arg1)")
  public static char drm_match_cea_mode(Ptr<drm_display_mode> to_match) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_match_cea_mode_clock_tolerance((const struct drm_display_mode *)$arg1, $arg2)")
  public static char drm_match_cea_mode_clock_tolerance(Ptr<drm_display_mode> to_match,
      @Unsigned int clock_tolerance) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_match_hdmi_mode((const struct drm_display_mode *)$arg1)")
  public static char drm_match_hdmi_mode(Ptr<drm_display_mode> to_match) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_memcpy_from_wc($arg1, (const struct iosys_map *)$arg2, $arg3)")
  public static void drm_memcpy_from_wc(Ptr<iosys_map> dst, Ptr<iosys_map> src,
      @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_memcpy_init_early() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_memory_stats_is_zero((const struct drm_memory_stats *)$arg1)")
  public static int drm_memory_stats_is_zero(Ptr<drm_memory_stats> stats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_minor> drm_minor_acquire(Ptr<xarray> minor_xa, @Unsigned int minor_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_minor_alloc(Ptr<drm_device> dev, drm_minor_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_minor_alloc_release(Ptr<drm_device> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_minor_register(Ptr<drm_device> dev, drm_minor_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_minor_release(Ptr<drm_minor> minor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_minor_unregister(Ptr<drm_device> dev, drm_minor_type type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int drm_mipi_dsi_get_input_bus_fmt(mipi_dsi_pixel_format dsi_format) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mm_init(Ptr<drm_mm> mm, @Unsigned long start, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mm_insert_node_in_range((const struct drm_mm*)$arg1, (const struct drm_mm_node*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static int drm_mm_insert_node_in_range(Ptr<drm_mm> mm, Ptr<drm_mm_node> node,
      @Unsigned long size, @Unsigned long alignment, @Unsigned long color,
      @Unsigned long range_start, @Unsigned long range_end, drm_mm_insert_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mm_interval_tree_add_node(Ptr<drm_mm_node> hole_node,
      Ptr<drm_mm_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mm_interval_tree_augment_rotate(Ptr<rb_node> rb_old, Ptr<rb_node> rb_new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mm_interval_tree_remove(Ptr<drm_mm_node> node, Ptr<rb_root_cached> root) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mm_print((const struct drm_mm *)$arg1, $arg2)")
  public static void drm_mm_print(Ptr<drm_mm> mm, Ptr<drm_printer> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mm_remove_node(Ptr<drm_mm_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mm_reserve_node(Ptr<drm_mm> mm, Ptr<drm_mm_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_mm_scan_add_block(Ptr<drm_mm_scan> scan, Ptr<drm_mm_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_mm_node> drm_mm_scan_color_evict(Ptr<drm_mm_scan> scan) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mm_scan_init_with_range(Ptr<drm_mm_scan> scan, Ptr<drm_mm> mm,
      @Unsigned long size, @Unsigned long alignment, @Unsigned long color, @Unsigned long start,
      @Unsigned long end, drm_mm_insert_mode mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_mm_scan_remove_block(Ptr<drm_mm_scan> scan, Ptr<drm_mm_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mm_takedown(Ptr<drm_mm> mm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_addfb(Ptr<drm_device> dev, Ptr<drm_mode_fb_cmd> or,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_addfb2(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_addfb2_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_addfb_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_atomic_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_closefb_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_compare($arg1, (const struct list_head *)$arg2, (const struct list_head *)$arg3)")
  public static int drm_mode_compare(Ptr<?> priv, Ptr<list_head> lh_a, Ptr<list_head> lh_b) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_config_cleanup(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_config_helper_resume(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_config_helper_suspend(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_config_init_release(Ptr<drm_device> dev, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_config_reset(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_config_validate(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_convert_to_umode($arg1, (const struct drm_display_mode *)$arg2)")
  public static void drm_mode_convert_to_umode(Ptr<drm_mode_modeinfo> out,
      Ptr<drm_display_mode> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_convert_umode($arg1, $arg2, (const struct drm_mode_modeinfo *)$arg3)")
  public static int drm_mode_convert_umode(Ptr<drm_device> dev, Ptr<drm_display_mode> out,
      Ptr<drm_mode_modeinfo> in) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_copy($arg1, (const struct drm_display_mode *)$arg2)")
  public static void drm_mode_copy(Ptr<drm_display_mode> dst, Ptr<drm_display_mode> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_display_mode> drm_mode_create(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_aspect_ratio_property(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_colorspace_property(Ptr<drm_connector> connector,
      @Unsigned int supported_colorspaces) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_content_type_property(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_dp_colorspace_property(Ptr<drm_connector> connector,
      @Unsigned int supported_colorspaces) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_dumb_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_dvi_i_properties(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_display_mode> drm_mode_create_from_cmdline_mode(Ptr<drm_device> dev,
      Ptr<drm_cmdline_mode> cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_hdmi_colorspace_property(Ptr<drm_connector> connector,
      @Unsigned int supported_colorspaces) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_lease_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> lessor_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_scaling_mode_property(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_standard_properties(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_suggested_offset_properties(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_create_tile_group($arg1, (const u8 *)$arg2)")
  public static Ptr<drm_tile_group> drm_mode_create_tile_group(Ptr<drm_device> dev,
      String topology) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_tv_margin_properties(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_create_tv_properties(Ptr<drm_device> dev,
      @Unsigned int supported_tv_modes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_create_tv_properties_legacy($arg1, $arg2, (const const u8 **)$arg3)")
  public static int drm_mode_create_tv_properties_legacy(Ptr<drm_device> dev,
      @Unsigned int num_modes, Ptr<String> modes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_createblob_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_crtc_set_gamma_size(Ptr<drm_crtc> crtc, int gamma_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_crtc_set_obj_prop(Ptr<drm_mode_object> obj, Ptr<drm_property> property,
      @Unsigned @OriginalName("uint64_t") long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_cursor2_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_cursor_common(Ptr<drm_device> dev, Ptr<drm_mode_cursor2> req,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_cursor_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_cursor_universal(Ptr<drm_crtc> crtc, Ptr<drm_mode_cursor2> req,
      Ptr<drm_file> file_priv, Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_debug_printmodeline((const struct drm_display_mode *)$arg1)")
  public static void drm_mode_debug_printmodeline(Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_destroy(Ptr<drm_device> dev, Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_destroy_dumb_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_destroyblob_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_detailed($arg1, (const struct drm_edid *)$arg2, (const struct detailed_timing *)$arg3)")
  public static Ptr<drm_display_mode> drm_mode_detailed(Ptr<drm_connector> connector,
      Ptr<drm_edid> drm_edid, Ptr<detailed_timing> timing) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_dirtyfb_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_duplicate($arg1, (const struct drm_display_mode *)$arg2)")
  public static Ptr<drm_display_mode> drm_mode_duplicate(Ptr<drm_device> dev,
      Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_equal((const struct drm_display_mode *)$arg1, (const struct drm_display_mode *)$arg2)")
  public static boolean drm_mode_equal(Ptr<drm_display_mode> mode1, Ptr<drm_display_mode> mode2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_equal_no_clocks((const struct drm_display_mode *)$arg1, (const struct drm_display_mode *)$arg2)")
  public static boolean drm_mode_equal_no_clocks(Ptr<drm_display_mode> mode1,
      Ptr<drm_display_mode> mode2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_equal_no_clocks_no_stereo((const struct drm_display_mode *)$arg1, (const struct drm_display_mode *)$arg2)")
  public static boolean drm_mode_equal_no_clocks_no_stereo(Ptr<drm_display_mode> mode1,
      Ptr<drm_display_mode> mode2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_display_mode> drm_mode_find_dmt(Ptr<drm_device> dev, int hsize, int vsize,
      int fresh, boolean rb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_fixup_1366x768(Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_gamma_get_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_gamma_set_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_get_hv_timing((const struct drm_display_mode *)$arg1, $arg2, $arg3)")
  public static void drm_mode_get_hv_timing(Ptr<drm_display_mode> mode,
      Ptr<java.lang.Integer> hdisplay, Ptr<java.lang.Integer> vdisplay) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_get_lease_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> lessee_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_get_tile_group($arg1, (const u8 *)$arg2)")
  public static Ptr<drm_tile_group> drm_mode_get_tile_group(Ptr<drm_device> dev, String topology) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_getblob_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_getconnector(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_getcrtc(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_getencoder(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_getfb(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_getfb2_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_getplane(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_getplane_res(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_getproperty_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_getresources(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_init($arg1, (const struct drm_display_mode *)$arg2)")
  public static void drm_mode_init(Ptr<drm_display_mode> dst, Ptr<drm_display_mode> src) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_is_420((const struct drm_display_info *)$arg1, (const struct drm_display_mode *)$arg2)")
  public static boolean drm_mode_is_420(Ptr<drm_display_info> display, Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_is_420_also((const struct drm_display_info *)$arg1, (const struct drm_display_mode *)$arg2)")
  public static boolean drm_mode_is_420_also(Ptr<drm_display_info> display,
      Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_is_420_only((const struct drm_display_info *)$arg1, (const struct drm_display_mode *)$arg2)")
  public static boolean drm_mode_is_420_only(Ptr<drm_display_info> display,
      Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("uint32_t") int drm_mode_legacy_fb_format(
      @Unsigned @OriginalName("uint32_t") int bpp, @Unsigned @OriginalName("uint32_t") int depth) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_list_lessees_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> lessor_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_match((const struct drm_display_mode *)$arg1, (const struct drm_display_mode *)$arg2, $arg3)")
  public static boolean drm_mode_match(Ptr<drm_display_mode> mode1, Ptr<drm_display_mode> mode2,
      @Unsigned int match_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_mmap_dumb_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_property> drm_mode_obj_find_prop_id(Ptr<drm_mode_object> obj,
      @Unsigned @OriginalName("uint32_t") int prop_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_obj_get_properties_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_obj_set_property_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_object_add(Ptr<drm_device> dev, Ptr<drm_mode_object> obj,
      @Unsigned @OriginalName("uint32_t") int obj_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_mode_object> drm_mode_object_find(Ptr<drm_device> dev,
      Ptr<drm_file> file_priv, @Unsigned @OriginalName("uint32_t") int id,
      @Unsigned @OriginalName("uint32_t") int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_object_get(Ptr<drm_mode_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_object_get_properties(Ptr<drm_mode_object> obj, boolean atomic,
      Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> prop_ptr,
      Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> prop_values,
      Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> arg_count_props) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_mode_object_lease_required(
      @Unsigned @OriginalName("uint32_t") int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_object_put(Ptr<drm_mode_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_object_register(Ptr<drm_device> dev, Ptr<drm_mode_object> obj) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_object_unregister(Ptr<drm_device> dev, Ptr<drm_mode_object> object) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_page_flip_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_parse_cmdline_extra((const u8 *)$arg1, $arg2, $arg3, (const struct drm_connector *)$arg4, $arg5)")
  public static int drm_mode_parse_cmdline_extra(String str, int length, boolean freestanding,
      Ptr<drm_connector> connector, Ptr<drm_cmdline_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_parse_cmdline_named_mode((const u8 *)$arg1, $arg2, $arg3)")
  public static int drm_mode_parse_cmdline_named_mode(String name, @Unsigned int name_end,
      Ptr<drm_cmdline_mode> cmdline_mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_parse_command_line_for_connector((const u8 *)$arg1, (const struct drm_connector *)$arg2, $arg3)")
  public static boolean drm_mode_parse_command_line_for_connector(String mode_option,
      Ptr<drm_connector> connector, Ptr<drm_cmdline_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_parse_panel_orientation((const u8 *)$arg1, $arg2)")
  public static int drm_mode_parse_panel_orientation(String delim, Ptr<drm_cmdline_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_plane_set_obj_prop(Ptr<drm_plane> plane, Ptr<drm_property> property,
      @Unsigned @OriginalName("uint64_t") long value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_probed_add(Ptr<drm_connector> connector, Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_prune_invalid(Ptr<drm_device> dev, Ptr<list_head> mode_list,
      boolean verbose) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_put_tile_group(Ptr<drm_device> dev, Ptr<drm_tile_group> tg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_revoke_lease_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> lessor_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_rmfb(Ptr<drm_device> dev, @Unsigned int fb_id,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_rmfb_ioctl(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_rmfb_work_fn(Ptr<work_struct> w) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_set_config_internal(Ptr<drm_mode_set> set) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_set_crtcinfo(Ptr<drm_display_mode> p, int adjust_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_set_name(Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_setcrtc(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_mode_setplane(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_mode_sort(Ptr<list_head> mode_list) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_std($arg1, (const struct drm_edid *)$arg2, (const struct std_timing *)$arg3)")
  public static Ptr<drm_display_mode> drm_mode_std(Ptr<drm_connector> connector,
      Ptr<drm_edid> drm_edid, Ptr<std_timing> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_validate_driver($arg1, (const struct drm_display_mode *)$arg2)")
  public static drm_mode_status drm_mode_validate_driver(Ptr<drm_device> dev,
      Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_validate_size((const struct drm_display_mode *)$arg1, $arg2, $arg3)")
  public static drm_mode_status drm_mode_validate_size(Ptr<drm_display_mode> mode, int maxX,
      int maxY) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_validate_ycbcr420((const struct drm_display_mode *)$arg1, $arg2)")
  public static drm_mode_status drm_mode_validate_ycbcr420(Ptr<drm_display_mode> mode,
      Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_mode_vrefresh((const struct drm_display_mode *)$arg1)")
  public static int drm_mode_vrefresh(Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_modeset_acquire_fini(Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_modeset_acquire_init(Ptr<drm_modeset_acquire_ctx> ctx,
      @Unsigned @OriginalName("uint32_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_modeset_backoff(Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_modeset_drop_locks(Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_modeset_lock_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_modeset_lock_all_ctx(Ptr<drm_device> dev,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_modeset_lock_init(Ptr<drm_modeset_lock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_modeset_lock_single_interruptible(Ptr<drm_modeset_lock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_modeset_register_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_modeset_unlock(Ptr<drm_modeset_lock> lock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_modeset_unlock_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_modeset_unregister_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_monitor_supports_rb((const struct drm_edid *)$arg1)")
  public static boolean drm_monitor_supports_rb(Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_name_info(Ptr<seq_file> m, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_need_swiotlb(int dma_bits) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_new_set_master(Ptr<drm_device> dev, Ptr<drm_file> fpriv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_noop(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_object_attach_property(Ptr<drm_mode_object> obj,
      Ptr<drm_property> property, @Unsigned @OriginalName("uint64_t") long init_val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_object_property_get_default_value(Ptr<drm_mode_object> obj,
      Ptr<drm_property> property, Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_object_property_get_value(Ptr<drm_mode_object> obj,
      Ptr<drm_property> property, Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_object_property_set_value(Ptr<drm_mode_object> obj,
      Ptr<drm_property> property, @Unsigned @OriginalName("uint64_t") long val) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_open(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_open_helper(Ptr<file> filp, Ptr<drm_minor> minor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_add(Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_panel_add_follower(Ptr<device> follower_dev,
      Ptr<drm_panel_follower> follower) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_bridge> drm_panel_bridge_add(Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_bridge> drm_panel_bridge_add_typed(Ptr<drm_panel> panel,
      @Unsigned int connector_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_connector> drm_panel_bridge_connector(Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_bridge_remove(Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_panel_bridge_set_orientation(Ptr<drm_connector> connector,
      Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_disable(Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_enable(Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_panel> drm_panel_get(Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_panel_get_modes(Ptr<drm_panel> panel, Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_panel_init($arg1, $arg2, (const struct drm_panel_funcs *)$arg3, $arg4)")
  public static void drm_panel_init(Ptr<drm_panel> panel, Ptr<device> dev,
      Ptr<drm_panel_funcs> funcs, int connector_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_panel_of_backlight(Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_prepare(Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_put(Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_put_void(Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_remove(Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_remove_follower(Ptr<drm_panel_follower> follower) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_remove_follower_void(Ptr<?> follower) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panel_unprepare(Ptr<drm_panel> panel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panic(Ptr<kmsg_dumper> dumper, Ptr<kmsg_dump_detail> detail) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panic_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panic_fill(Ptr<drm_scanout_buffer> sb, Ptr<drm_rect> clip,
      @Unsigned int color) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panic_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_panic_is_enabled(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panic_register(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_panic_unregister(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_parse_cea_ext($arg1, (const struct drm_edid *)$arg2)")
  public static void drm_parse_cea_ext(Ptr<drm_connector> connector, Ptr<drm_edid> drm_edid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_parse_hdmi_deep_color_info($arg1, (const u8 *)$arg2)")
  public static void drm_parse_hdmi_deep_color_info(Ptr<drm_connector> connector,
      Ptr<java.lang.Character> hdmi) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_parse_tiled_block($arg1, (const struct displayid_block *)$arg2)")
  public static void drm_parse_tiled_block(Ptr<drm_connector> connector,
      Ptr<displayid_block> block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_parse_vesa_mso_data($arg1, (const struct displayid_block *)$arg2)")
  public static void drm_parse_vesa_mso_data(Ptr<drm_connector> connector,
      Ptr<displayid_block> block) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_pci_set_busid(Ptr<drm_device> dev, Ptr<drm_master> master) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_plane_add_size_hints_property($arg1, (const struct drm_plane_size_hint *)$arg2, $arg3)")
  public static int drm_plane_add_size_hints_property(Ptr<drm_plane> plane,
      Ptr<drm_plane_size_hint> hints, int num_hints) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_plane_cleanup(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_plane_create_alpha_property(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_plane_create_blend_mode_property(Ptr<drm_plane> plane,
      @Unsigned int supported_modes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_plane_create_color_properties(Ptr<drm_plane> plane,
      @Unsigned int supported_encodings, @Unsigned int supported_ranges,
      drm_color_encoding default_encoding, drm_color_range default_range) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_plane_create_rotation_property(Ptr<drm_plane> plane, @Unsigned int rotation,
      @Unsigned int supported_rotations) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_plane_create_scaling_filter_property(Ptr<drm_plane> plane,
      @Unsigned int supported_filters) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_plane_create_zpos_immutable_property(Ptr<drm_plane> plane,
      @Unsigned int zpos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_plane_create_zpos_property(Ptr<drm_plane> plane, @Unsigned int zpos,
      @Unsigned int min, @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_plane_enable_fb_damage_clips(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_plane_force_disable(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_plane> drm_plane_from_index(Ptr<drm_device> dev, int idx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_plane_get_damage_clips((const struct drm_plane_state *)$arg1)")
  public static Ptr<drm_mode_rect> drm_plane_get_damage_clips(Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_plane_get_damage_clips_count((const struct drm_plane_state *)$arg1)")
  public static @Unsigned int drm_plane_get_damage_clips_count(Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_plane_has_format(Ptr<drm_plane> plane, @Unsigned int format,
      @Unsigned long modifier) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_plane_helper_destroy(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_plane_helper_disable_primary(Ptr<drm_plane> plane,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_plane_helper_update_primary(Ptr<drm_plane> plane, Ptr<drm_crtc> crtc,
      Ptr<drm_framebuffer> fb, int crtc_x, int crtc_y, @Unsigned int crtc_w, @Unsigned int crtc_h,
      @Unsigned @OriginalName("uint32_t") int src_x, @Unsigned @OriginalName("uint32_t") int src_y,
      @Unsigned @OriginalName("uint32_t") int src_w, @Unsigned @OriginalName("uint32_t") int src_h,
      Ptr<drm_modeset_acquire_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_plane_register_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_plane_unregister_all(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("__poll_t") int drm_poll(Ptr<file> filp,
      Ptr<poll_table_struct> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_prime_add_buf_handle(Ptr<drm_prime_file_private> prime_fpriv,
      Ptr<dma_buf> dma_buf, @Unsigned @OriginalName("uint32_t") int handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_prime_destroy_file_private(Ptr<drm_prime_file_private> prime_fpriv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_prime_fd_to_handle_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_prime_gem_destroy(Ptr<drm_gem_object> obj, Ptr<sg_table> sg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long drm_prime_get_contiguous_size(Ptr<sg_table> sgt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_prime_handle_to_fd_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_prime_init_file_private(Ptr<drm_prime_file_private> prime_fpriv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> drm_prime_pages_to_sg(Ptr<drm_device> dev, Ptr<Ptr<page>> pages,
      @Unsigned int nr_pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_prime_remove_buf_handle(Ptr<drm_prime_file_private> prime_fpriv,
      @Unsigned @OriginalName("uint32_t") int handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_prime_sg_to_dma_addr_array(Ptr<sg_table> sgt,
      Ptr<java.lang. @Unsigned @OriginalName("dma_addr_t") Long> addrs, int max_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_prime_sg_to_page_array(Ptr<sg_table> sgt, Ptr<Ptr<page>> pages,
      int max_entries) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_print_bits($arg1, $arg2, (const const u8 **)$arg3, $arg4)")
  public static void drm_print_bits(Ptr<drm_printer> p, @Unsigned long value, Ptr<String> bits,
      @Unsigned int nbits) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_print_hex_dump($arg1, (const u8 *)$arg2, (const u8 *)$arg3, $arg4)")
  public static void drm_print_hex_dump(Ptr<drm_printer> p, String prefix,
      Ptr<java.lang.Character> buf, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_print_memory_stats($arg1, (const struct drm_memory_stats *)$arg2, $arg3, (const u8 *)$arg4)")
  public static void drm_print_memory_stats(Ptr<drm_printer> p, Ptr<drm_memory_stats> stats,
      drm_gem_object_status supported_status, String region) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_print_regset32(Ptr<drm_printer> p, Ptr<debugfs_regset32> regset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_printf($arg1, (const u8 *)$arg2, $arg3_)")
  public static void drm_printf(Ptr<drm_printer> p, String f, java.lang.Object... param2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_privacy_screen_call_notifier_chain(Ptr<drm_privacy_screen> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_privacy_screen_device_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_privacy_screen_get($arg1, (const u8 *)$arg2)")
  public static Ptr<drm_privacy_screen> drm_privacy_screen_get(Ptr<device> dev, String con_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_privacy_screen_get_state(Ptr<drm_privacy_screen> priv,
      Ptr<drm_privacy_screen_status> sw_state_ret, Ptr<drm_privacy_screen_status> hw_state_ret) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_privacy_screen_lookup_add(Ptr<drm_privacy_screen_lookup> lookup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_privacy_screen_lookup_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_privacy_screen_lookup_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_privacy_screen_lookup_remove(Ptr<drm_privacy_screen_lookup> lookup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_privacy_screen_put(Ptr<drm_privacy_screen> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_privacy_screen_register($arg1, (const struct drm_privacy_screen_ops *)$arg2, $arg3)")
  public static Ptr<drm_privacy_screen> drm_privacy_screen_register(Ptr<device> parent,
      Ptr<drm_privacy_screen_ops> ops, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_privacy_screen_register_notifier(Ptr<drm_privacy_screen> priv,
      Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_privacy_screen_set_sw_state(Ptr<drm_privacy_screen> priv,
      drm_privacy_screen_status sw_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_privacy_screen_unregister(Ptr<drm_privacy_screen> priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_privacy_screen_unregister_notifier(Ptr<drm_privacy_screen> priv,
      Ptr<notifier_block> nb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_probe_ddc(Ptr<i2c_adapter> adapter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_property_add_enum($arg1, $arg2, (const u8 *)$arg3)")
  public static int drm_property_add_enum(Ptr<drm_property> property,
      @Unsigned @OriginalName("uint64_t") long value, String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_property_blob> drm_property_blob_get(Ptr<drm_property_blob> blob) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_property_blob_put(Ptr<drm_property_blob> blob) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_property_change_valid_get(Ptr<drm_property> property,
      @Unsigned @OriginalName("uint64_t") long value, Ptr<Ptr<drm_mode_object>> ref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_property_change_valid_put(Ptr<drm_property> property,
      Ptr<drm_mode_object> ref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_property_create($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static Ptr<drm_property> drm_property_create(Ptr<drm_device> dev, @Unsigned int flags,
      String name, int num_values) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_property_create_bitmask($arg1, $arg2, (const u8 *)$arg3, (const struct drm_prop_enum_list *)$arg4, $arg5, $arg6)")
  public static Ptr<drm_property> drm_property_create_bitmask(Ptr<drm_device> dev,
      @Unsigned int flags, String name, Ptr<drm_prop_enum_list> props, int num_props,
      @Unsigned @OriginalName("uint64_t") long supported_bits) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_property_create_blob($arg1, $arg2, (const void *)$arg3)")
  public static Ptr<drm_property_blob> drm_property_create_blob(Ptr<drm_device> dev,
      @Unsigned long length, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_property_create_bool($arg1, $arg2, (const u8 *)$arg3)")
  public static Ptr<drm_property> drm_property_create_bool(Ptr<drm_device> dev, @Unsigned int flags,
      String name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_property_create_enum($arg1, $arg2, (const u8 *)$arg3, (const struct drm_prop_enum_list *)$arg4, $arg5)")
  public static Ptr<drm_property> drm_property_create_enum(Ptr<drm_device> dev, @Unsigned int flags,
      String name, Ptr<drm_prop_enum_list> props, int num_values) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_property_create_object($arg1, $arg2, (const u8 *)$arg3, $arg4)")
  public static Ptr<drm_property> drm_property_create_object(Ptr<drm_device> dev,
      @Unsigned int flags, String name, @Unsigned @OriginalName("uint32_t") int type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_property_create_range($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static Ptr<drm_property> drm_property_create_range(Ptr<drm_device> dev,
      @Unsigned int flags, String name, @Unsigned @OriginalName("uint64_t") long min,
      @Unsigned @OriginalName("uint64_t") long max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_property_create_signed_range($arg1, $arg2, (const u8 *)$arg3, $arg4, $arg5)")
  public static Ptr<drm_property> drm_property_create_signed_range(Ptr<drm_device> dev,
      @Unsigned int flags, String name, @OriginalName("int64_t") long min,
      @OriginalName("int64_t") long max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_property_destroy(Ptr<drm_device> dev, Ptr<drm_property> property) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_property_destroy_user_blobs(Ptr<drm_device> dev, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_property_free_blob(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_property_blob> drm_property_lookup_blob(Ptr<drm_device> dev,
      @Unsigned @OriginalName("uint32_t") int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_property_replace_blob(Ptr<Ptr<drm_property_blob>> blob,
      Ptr<drm_property_blob> new_blob) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_property_replace_blob_from_id(Ptr<drm_device> dev,
      Ptr<Ptr<drm_property_blob>> blob, @Unsigned @OriginalName("uint64_t") long blob_id,
      @OriginalName("ssize_t") long expected_size, @OriginalName("ssize_t") long expected_elem_size,
      Ptr<java.lang. @OriginalName("bool") Boolean> replaced) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_property_replace_global_blob($arg1, $arg2, $arg3, (const void *)$arg4, $arg5, $arg6)")
  public static int drm_property_replace_global_blob(Ptr<drm_device> dev,
      Ptr<Ptr<drm_property_blob>> replace, @Unsigned long length, Ptr<?> data,
      Ptr<drm_mode_object> obj_holds_id, Ptr<drm_property> prop_holds_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_put_dev(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_puts($arg1, (const u8 *)$arg2)")
  public static void drm_puts(Ptr<drm_printer> p, String str) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_queue_vblank_event(Ptr<drm_device> dev, @Unsigned int pipe,
      @Unsigned long req_seq, Ptr<drm_wait_vblank> vblwait, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ssize_t") long drm_read(Ptr<file> filp, String buffer,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_rect_calc_hscale((const struct drm_rect *)$arg1, (const struct drm_rect *)$arg2, $arg3, $arg4)")
  public static int drm_rect_calc_hscale(Ptr<drm_rect> src, Ptr<drm_rect> dst, int min_hscale,
      int max_hscale) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_rect_calc_vscale((const struct drm_rect *)$arg1, (const struct drm_rect *)$arg2, $arg3, $arg4)")
  public static int drm_rect_calc_vscale(Ptr<drm_rect> src, Ptr<drm_rect> dst, int min_vscale,
      int max_vscale) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_rect_clip_scaled($arg1, $arg2, (const struct drm_rect *)$arg3)")
  public static boolean drm_rect_clip_scaled(Ptr<drm_rect> src, Ptr<drm_rect> dst,
      Ptr<drm_rect> clip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_rect_debug_print((const u8 *)$arg1, (const struct drm_rect *)$arg2, $arg3)")
  public static void drm_rect_debug_print(String prefix, Ptr<drm_rect> r, boolean fixed_point) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_rect_intersect($arg1, (const struct drm_rect *)$arg2)")
  public static boolean drm_rect_intersect(Ptr<drm_rect> r1, Ptr<drm_rect> r2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_rect_rotate(Ptr<drm_rect> r, int width, int height,
      @Unsigned int rotation) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_rect_rotate_inv(Ptr<drm_rect> r, int width, int height,
      @Unsigned int rotation) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_release(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_release_noglobal(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_reset_display_info(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int drm_rotation_simplify(@Unsigned int rotation,
      @Unsigned int supported_rotations) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_self_refresh_helper_alter_state(Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_self_refresh_helper_cleanup(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_self_refresh_helper_entry_work(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_self_refresh_helper_init(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_self_refresh_helper_update_avg_times(Ptr<drm_atomic_state> state,
      @Unsigned int commit_time_ms, @Unsigned int new_self_refresh_mask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_send_event(Ptr<drm_device> dev, Ptr<drm_pending_event> e) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_send_event_helper(Ptr<drm_device> dev, Ptr<drm_pending_event> e,
      @OriginalName("ktime_t") long timestamp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_send_event_locked(Ptr<drm_device> dev, Ptr<drm_pending_event> e) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_send_event_timestamp_locked(Ptr<drm_device> dev, Ptr<drm_pending_event> e,
      @OriginalName("ktime_t") long timestamp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_set_busid(Ptr<drm_device> dev, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_set_preferred_mode(Ptr<drm_connector> connector, int hpref, int vpref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_setclientcap(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_setmaster_ioctl(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_setup_crtcs_fb(Ptr<drm_fb_helper> fb_helper) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_setversion(Ptr<drm_device> dev, Ptr<?> data, Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_show_fdinfo(Ptr<seq_file> m, Ptr<file> f) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_show_memory_stats(Ptr<drm_printer> p, Ptr<drm_file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_simple_display_pipe_attach_bridge(Ptr<drm_simple_display_pipe> pipe,
      Ptr<drm_bridge> bridge) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_simple_display_pipe_init($arg1, $arg2, (const struct drm_simple_display_pipe_funcs *)$arg3, (const unsigned int *)$arg4, $arg5, (const long long unsigned int *)$arg6, $arg7)")
  public static int drm_simple_display_pipe_init(Ptr<drm_device> dev,
      Ptr<drm_simple_display_pipe> pipe, Ptr<drm_simple_display_pipe_funcs> funcs,
      Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> formats,
      @Unsigned int format_count,
      Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> format_modifiers,
      Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_simple_encoder_init(Ptr<drm_device> dev, Ptr<drm_encoder> encoder,
      int encoder_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_simple_kms_crtc_check(Ptr<drm_crtc> crtc, Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_simple_kms_crtc_destroy_state(Ptr<drm_crtc> crtc,
      Ptr<drm_crtc_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_simple_kms_crtc_disable(Ptr<drm_crtc> crtc, Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_simple_kms_crtc_disable_vblank(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_crtc_state> drm_simple_kms_crtc_duplicate_state(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_simple_kms_crtc_enable(Ptr<drm_crtc> crtc, Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_simple_kms_crtc_enable_vblank(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_simple_kms_crtc_mode_valid($arg1, (const struct drm_display_mode *)$arg2)")
  public static drm_mode_status drm_simple_kms_crtc_mode_valid(Ptr<drm_crtc> crtc,
      Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_simple_kms_crtc_reset(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_simple_kms_format_mod_supported(Ptr<drm_plane> plane,
      @Unsigned @OriginalName("uint32_t") int format,
      @Unsigned @OriginalName("uint64_t") long modifier) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_simple_kms_plane_atomic_check(Ptr<drm_plane> plane,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_simple_kms_plane_atomic_update(Ptr<drm_plane> plane,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_simple_kms_plane_begin_fb_access(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> new_plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_simple_kms_plane_cleanup_fb(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_simple_kms_plane_destroy_state(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_plane_state> drm_simple_kms_plane_duplicate_state(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_simple_kms_plane_end_fb_access(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> new_plane_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_simple_kms_plane_prepare_fb(Ptr<drm_plane> plane,
      Ptr<drm_plane_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_simple_kms_plane_reset(Ptr<drm_plane> plane) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_state_dump(Ptr<drm_device> dev, Ptr<drm_printer> p) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_state_info(Ptr<seq_file> m, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_stub_open(Ptr<inode> inode, Ptr<file> filp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_syncobj_add_point(Ptr<drm_syncobj> syncobj, Ptr<dma_fence_chain> chain,
      Ptr<dma_fence> fence, @Unsigned @OriginalName("uint64_t") long point) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_array_find(Ptr<drm_file> file_private, Ptr<?> user_handles,
      @Unsigned @OriginalName("uint32_t") int count_handles,
      Ptr<Ptr<Ptr<drm_syncobj>>> syncobjs_out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_syncobj_array_free(Ptr<Ptr<drm_syncobj>> syncobjs,
      @Unsigned @OriginalName("uint32_t") int count) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long drm_syncobj_array_wait_timeout(Ptr<Ptr<drm_syncobj>> syncobjs,
      Ptr<?> user_points, @Unsigned @OriginalName("uint32_t") int count,
      @Unsigned @OriginalName("uint32_t") int flags, long timeout,
      Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> idx,
      Ptr<java.lang. @OriginalName("ktime_t") Long> deadline) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_create_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_destroy_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_eventfd_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_fd_to_handle_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_syncobj_fence_add_wait(Ptr<drm_syncobj> syncobj,
      Ptr<syncobj_wait_entry> wait) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_file_release(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_syncobj> drm_syncobj_find(Ptr<drm_file> file_private,
      @Unsigned int handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_find_fence(Ptr<drm_file> file_private, @Unsigned int handle,
      @Unsigned long point, @Unsigned long flags, Ptr<Ptr<dma_fence>> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_syncobj_free(Ptr<kref> kref) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_get_fd(Ptr<drm_syncobj> syncobj, Ptr<java.lang.Integer> p_fd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_get_handle(Ptr<drm_file> file_private, Ptr<drm_syncobj> syncobj,
      Ptr<java.lang. @Unsigned Integer> handle) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_handle_to_fd_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_syncobj_open(Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_query_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_syncobj_release(Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_release_handle(int id, Ptr<?> ptr, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_syncobj_replace_fence(Ptr<drm_syncobj> syncobj, Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_reset_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_signal_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_timeline_signal_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_timeline_wait_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_transfer_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_syncobj_wait_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_private) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_sysfb_build_fourcc_list($arg1, (const unsigned int *)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned long drm_sysfb_build_fourcc_list(Ptr<drm_device> dev,
      Ptr<java.lang. @Unsigned Integer> native_fourccs, @Unsigned long native_nfourccs,
      Ptr<java.lang. @Unsigned Integer> fourccs_out, @Unsigned long nfourccs_out) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_sysfb_connector_helper_get_modes(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfb_crtc_atomic_destroy_state(Ptr<drm_crtc> crtc,
      Ptr<drm_crtc_state> crtc_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_crtc_state> drm_sysfb_crtc_atomic_duplicate_state(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_sysfb_crtc_helper_atomic_check(Ptr<drm_crtc> crtc,
      Ptr<drm_atomic_state> new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_sysfb_crtc_helper_mode_valid($arg1, (const struct drm_display_mode *)$arg2)")
  public static drm_mode_status drm_sysfb_crtc_helper_mode_valid(Ptr<drm_crtc> crtc,
      Ptr<drm_display_mode> mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfb_crtc_reset(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_sysfb_get_edid_block(Ptr<?> data, Ptr<java.lang.Character> buf,
      @Unsigned int block, @Unsigned long len) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct drm_format_info*)drm_sysfb_get_format_si($arg1, (const struct drm_sysfb_format *)$arg2, $arg3, (const struct screen_info *)$arg4))")
  public static Ptr<drm_format_info> drm_sysfb_get_format_si(Ptr<drm_device> dev,
      Ptr<drm_sysfb_format> formats, @Unsigned long nformats, Ptr<screen_info> si) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_sysfb_get_height_si($arg1, (const struct screen_info *)$arg2)")
  public static int drm_sysfb_get_height_si(Ptr<drm_device> dev, Ptr<screen_info> si) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_sysfb_get_memory_si($arg1, (const struct screen_info *)$arg2, $arg3)")
  public static Ptr<resource> drm_sysfb_get_memory_si(Ptr<drm_device> dev, Ptr<screen_info> si,
      Ptr<resource> res) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_sysfb_get_stride_si($arg1, (const struct screen_info *)$arg2, (const struct drm_format_info *)$arg3, $arg4, $arg5, $arg6)")
  public static int drm_sysfb_get_stride_si(Ptr<drm_device> dev, Ptr<screen_info> si,
      Ptr<drm_format_info> format, @Unsigned int width, @Unsigned int height, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_sysfb_get_validated_int($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int drm_sysfb_get_validated_int(Ptr<drm_device> dev, String name,
      @Unsigned long value, @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_sysfb_get_validated_int0($arg1, (const u8 *)$arg2, $arg3, $arg4)")
  public static int drm_sysfb_get_validated_int0(Ptr<drm_device> dev, String name,
      @Unsigned long value, @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_sysfb_get_visible_size_si($arg1, (const struct screen_info *)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned long drm_sysfb_get_visible_size_si(Ptr<drm_device> dev,
      Ptr<screen_info> si, @Unsigned int height, @Unsigned int stride, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_sysfb_get_width_si($arg1, (const struct screen_info *)$arg2)")
  public static int drm_sysfb_get_width_si(Ptr<drm_device> dev, Ptr<screen_info> si) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_sysfb_plane_helper_atomic_check(Ptr<drm_plane> plane,
      Ptr<drm_atomic_state> new_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfb_plane_helper_atomic_disable(Ptr<drm_plane> plane,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfb_plane_helper_atomic_update(Ptr<drm_plane> plane,
      Ptr<drm_atomic_state> state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_sysfb_plane_helper_get_scanout_buffer(Ptr<drm_plane> plane,
      Ptr<drm_scanout_buffer> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_sysfs_connector_add(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_sysfs_connector_add_late(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfs_connector_hotplug_event(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfs_connector_property_event(Ptr<drm_connector> connector,
      Ptr<drm_property> property) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfs_connector_remove(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfs_connector_remove_early(Ptr<drm_connector> connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfs_destroy() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfs_hotplug_event(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_sysfs_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfs_lease_event(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<device> drm_sysfs_minor_alloc(Ptr<drm_minor> minor) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_sysfs_release(Ptr<device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static long drm_timeout_abs_to_jiffies(@OriginalName("int64_t") long timeout_nsec) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_universal_plane_init($arg1, $arg2, $arg3, (const struct drm_plane_funcs *)$arg4, (const unsigned int *)$arg5, $arg6, (const long long unsigned int *)$arg7, $arg8, (const u8 *)$arg9, $arg10_)")
  public static int drm_universal_plane_init(Ptr<drm_device> dev, Ptr<drm_plane> plane,
      @Unsigned @OriginalName("uint32_t") int possible_crtcs, Ptr<drm_plane_funcs> funcs,
      Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> formats,
      @Unsigned int format_count,
      Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> format_modifiers,
      drm_plane_type type, String name, java.lang.Object... param9) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_update_vblank_count(Ptr<drm_device> dev, @Unsigned int pipe,
      boolean in_vblank_irq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vblank_cancel_pending_works(Ptr<drm_vblank_crtc> vblank) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long drm_vblank_count(Ptr<drm_device> dev, @Unsigned int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long drm_vblank_count_and_time(Ptr<drm_device> dev, @Unsigned int pipe,
      Ptr<java.lang. @OriginalName("ktime_t") Long> vblanktime) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vblank_disable_and_save(Ptr<drm_device> dev, @Unsigned int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_vblank_enable(Ptr<drm_device> dev, @Unsigned int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_vblank_get(Ptr<drm_device> dev, @Unsigned int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_vblank_init(Ptr<drm_device> dev, @Unsigned int num_crtcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vblank_init_release(Ptr<drm_device> dev, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vblank_put(Ptr<drm_device> dev, @Unsigned int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vblank_restore(Ptr<drm_device> dev, @Unsigned int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_vblank_work_cancel_sync(Ptr<drm_vblank_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vblank_work_flush(Ptr<drm_vblank_work> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vblank_work_flush_all(Ptr<drm_crtc> crtc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_vblank_work_init($arg1, $arg2, (void (*)(struct kthread_work*))$arg3)")
  public static void drm_vblank_work_init(Ptr<drm_vblank_work> work, Ptr<drm_crtc> crtc,
      Ptr<?> func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_vblank_work_schedule(Ptr<drm_vblank_work> work, @Unsigned long count,
      boolean nextonmiss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_vblank_worker_init(Ptr<drm_vblank_crtc> vblank) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_vma_node_allow(Ptr<drm_vma_offset_node> node, Ptr<drm_file> tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_vma_node_allow_once(Ptr<drm_vma_offset_node> node, Ptr<drm_file> tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean drm_vma_node_is_allowed(Ptr<drm_vma_offset_node> node, Ptr<drm_file> tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vma_node_revoke(Ptr<drm_vma_offset_node> node, Ptr<drm_file> tag) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_vma_offset_add(Ptr<drm_vma_offset_manager> mgr,
      Ptr<drm_vma_offset_node> node, @Unsigned long pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<drm_vma_offset_node> drm_vma_offset_lookup_locked(
      Ptr<drm_vma_offset_manager> mgr, @Unsigned long start, @Unsigned long pages) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vma_offset_manager_destroy(Ptr<drm_vma_offset_manager> mgr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vma_offset_manager_init(Ptr<drm_vma_offset_manager> mgr,
      @Unsigned long page_offset, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_vma_offset_remove(Ptr<drm_vma_offset_manager> mgr,
      Ptr<drm_vma_offset_node> node) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_wait_one_vblank(Ptr<drm_device> dev, @Unsigned int pipe) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_wait_vblank_ioctl(Ptr<drm_device> dev, Ptr<?> data,
      Ptr<drm_file> file_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_warn_on_modeset_not_all_locked(Ptr<drm_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_writeback_cleanup_job(Ptr<drm_writeback_job> job) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_writeback_connector_cleanup(Ptr<drm_device> dev, Ptr<?> data) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_writeback_connector_init($arg1, $arg2, (const struct drm_connector_funcs *)$arg3, (const struct drm_encoder_helper_funcs *)$arg4, (const unsigned int *)$arg5, $arg6, $arg7)")
  public static int drm_writeback_connector_init(Ptr<drm_device> dev,
      Ptr<drm_writeback_connector> wb_connector, Ptr<drm_connector_funcs> con_funcs,
      Ptr<drm_encoder_helper_funcs> enc_helper_funcs, Ptr<java.lang. @Unsigned Integer> formats,
      int n_formats, @Unsigned int possible_crtcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("drm_writeback_connector_init_with_encoder($arg1, $arg2, $arg3, (const struct drm_connector_funcs *)$arg4, (const unsigned int *)$arg5, $arg6)")
  public static int drm_writeback_connector_init_with_encoder(Ptr<drm_device> dev,
      Ptr<drm_writeback_connector> wb_connector, Ptr<drm_encoder> enc,
      Ptr<drm_connector_funcs> con_funcs, Ptr<java.lang. @Unsigned Integer> formats,
      int n_formats) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_writeback_fence_get_driver_name($arg1))")
  public static String drm_writeback_fence_get_driver_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)drm_writeback_fence_get_timeline_name($arg1))")
  public static String drm_writeback_fence_get_timeline_name(Ptr<dma_fence> fence) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dma_fence> drm_writeback_get_out_fence(
      Ptr<drm_writeback_connector> wb_connector) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_writeback_prepare_job(Ptr<drm_writeback_job> job) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_writeback_queue_job(Ptr<drm_writeback_connector> wb_connector,
      Ptr<drm_connector_state> conn_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int drm_writeback_set_fb(Ptr<drm_connector_state> conn_state,
      Ptr<drm_framebuffer> fb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void drm_writeback_signal_completion(Ptr<drm_writeback_connector> wb_connector,
      int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_fb_cmd2"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_fb_cmd2 extends Struct {
    public @Unsigned int fb_id;

    public @Unsigned int width;

    public @Unsigned int height;

    public @Unsigned int pixel_format;

    public @Unsigned int flags;

    public @Unsigned int @Size(4) [] handles;

    public @Unsigned int @Size(4) [] pitches;

    public @Unsigned int @Size(4) [] offsets;

    public @Unsigned long @Size(4) [] modifier;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_modeset_acquire_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_modeset_acquire_ctx extends Struct {
    public ww_acquire_ctx ww_ctx;

    public Ptr<drm_modeset_lock> contended;

    public @Unsigned @OriginalName("depot_stack_handle_t") int stack_depot;

    public list_head locked;

    public boolean trylock_only;

    public boolean interruptible;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_modeset_lock"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_modeset_lock extends Struct {
    public ww_mutex mutex;

    public list_head head;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_config_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_config_funcs extends Struct {
    public Ptr<?> fb_create;

    public Ptr<?> get_format_info;

    public Ptr<?> mode_valid;

    public Ptr<?> atomic_check;

    public Ptr<?> atomic_commit;

    public Ptr<?> atomic_state_alloc;

    public Ptr<?> atomic_state_clear;

    public Ptr<?> atomic_state_free;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_device extends Struct {
    public int if_version;

    public kref ref;

    public Ptr<device> dev;

    public Ptr<device> dma_dev;

    public managed_of_drm_device managed;

    public Ptr<drm_driver> driver;

    public Ptr<?> dev_private;

    public Ptr<drm_minor> primary;

    public Ptr<drm_minor> render;

    public Ptr<drm_minor> accel;

    public boolean registered;

    public Ptr<drm_master> master;

    public @Unsigned int driver_features;

    public boolean unplugged;

    public Ptr<inode> anon_inode;

    public String unique;

    public mutex struct_mutex;

    public mutex master_mutex;

    public atomic_t open_count;

    public mutex filelist_mutex;

    public list_head filelist;

    public list_head filelist_internal;

    public mutex clientlist_mutex;

    public list_head clientlist;

    public boolean vblank_disable_immediate;

    public Ptr<drm_vblank_crtc> vblank;

    public @OriginalName("spinlock_t") spinlock vblank_time_lock;

    public @OriginalName("spinlock_t") spinlock vbl_lock;

    public @Unsigned int max_vblank_count;

    public list_head vblank_event_list;

    public @OriginalName("spinlock_t") spinlock event_lock;

    public @Unsigned int num_crtcs;

    public drm_mode_config mode_config;

    public mutex object_name_lock;

    public idr object_name_idr;

    public Ptr<drm_vma_offset_manager> vma_offset_manager;

    public @OriginalName("drm_vram_mm") Ptr<?> vram_mm;

    public switch_power_state switch_power_state;

    public Ptr<drm_fb_helper> fb_helper;

    public Ptr<dentry> debugfs_root;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_format_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_format_info extends Struct {
    public @Unsigned int format;

    public char depth;

    public char num_planes;

    @InlineUnion(47969)
    public char @Size(4) [] cpp;

    @InlineUnion(47969)
    public char @Size(4) [] char_per_block;

    public char @Size(4) [] block_w;

    public char @Size(4) [] block_h;

    public char hsub;

    public char vsub;

    public boolean has_alpha;

    public boolean is_yuv;

    public boolean is_color_indexed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_display_mode"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_display_mode extends Struct {
    public int clock;

    public @Unsigned short hdisplay;

    public @Unsigned short hsync_start;

    public @Unsigned short hsync_end;

    public @Unsigned short htotal;

    public @Unsigned short hskew;

    public @Unsigned short vdisplay;

    public @Unsigned short vsync_start;

    public @Unsigned short vsync_end;

    public @Unsigned short vtotal;

    public @Unsigned short vscan;

    public @Unsigned int flags;

    public int crtc_clock;

    public @Unsigned short crtc_hdisplay;

    public @Unsigned short crtc_hblank_start;

    public @Unsigned short crtc_hblank_end;

    public @Unsigned short crtc_hsync_start;

    public @Unsigned short crtc_hsync_end;

    public @Unsigned short crtc_htotal;

    public @Unsigned short crtc_hskew;

    public @Unsigned short crtc_vdisplay;

    public @Unsigned short crtc_vblank_start;

    public @Unsigned short crtc_vblank_end;

    public @Unsigned short crtc_vsync_start;

    public @Unsigned short crtc_vsync_end;

    public @Unsigned short crtc_vtotal;

    public @Unsigned short width_mm;

    public @Unsigned short height_mm;

    public char type;

    public boolean expose_to_userspace;

    public list_head head;

    public char @Size(32) [] name;

    public drm_mode_status status;

    public hdmi_picture_aspect picture_aspect_ratio;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_config extends Struct {
    public mutex mutex;

    public drm_modeset_lock connection_mutex;

    public Ptr<drm_modeset_acquire_ctx> acquire_ctx;

    public mutex idr_mutex;

    public idr object_idr;

    public idr tile_idr;

    public mutex fb_lock;

    public int num_fb;

    public list_head fb_list;

    public @OriginalName("spinlock_t") spinlock connector_list_lock;

    public int num_connector;

    public ida connector_ida;

    public list_head connector_list;

    public llist_head connector_free_list;

    public work_struct connector_free_work;

    public int num_encoder;

    public list_head encoder_list;

    public int num_total_plane;

    public list_head plane_list;

    public raw_spinlock panic_lock;

    public int num_crtc;

    public list_head crtc_list;

    public list_head property_list;

    public list_head privobj_list;

    public @Unsigned int min_width;

    public @Unsigned int min_height;

    public @Unsigned int max_width;

    public @Unsigned int max_height;

    public Ptr<drm_mode_config_funcs> funcs;

    public boolean poll_enabled;

    public boolean poll_running;

    public boolean delayed_event;

    public delayed_work output_poll_work;

    public mutex blob_lock;

    public list_head property_blob_list;

    public Ptr<drm_property> edid_property;

    public Ptr<drm_property> dpms_property;

    public Ptr<drm_property> path_property;

    public Ptr<drm_property> tile_property;

    public Ptr<drm_property> link_status_property;

    public Ptr<drm_property> plane_type_property;

    public Ptr<drm_property> prop_src_x;

    public Ptr<drm_property> prop_src_y;

    public Ptr<drm_property> prop_src_w;

    public Ptr<drm_property> prop_src_h;

    public Ptr<drm_property> prop_crtc_x;

    public Ptr<drm_property> prop_crtc_y;

    public Ptr<drm_property> prop_crtc_w;

    public Ptr<drm_property> prop_crtc_h;

    public Ptr<drm_property> prop_fb_id;

    public Ptr<drm_property> prop_in_fence_fd;

    public Ptr<drm_property> prop_out_fence_ptr;

    public Ptr<drm_property> prop_crtc_id;

    public Ptr<drm_property> prop_fb_damage_clips;

    public Ptr<drm_property> prop_active;

    public Ptr<drm_property> prop_mode_id;

    public Ptr<drm_property> prop_vrr_enabled;

    public Ptr<drm_property> dvi_i_subconnector_property;

    public Ptr<drm_property> dvi_i_select_subconnector_property;

    public Ptr<drm_property> dp_subconnector_property;

    public Ptr<drm_property> tv_subconnector_property;

    public Ptr<drm_property> tv_select_subconnector_property;

    public Ptr<drm_property> legacy_tv_mode_property;

    public Ptr<drm_property> tv_mode_property;

    public Ptr<drm_property> tv_left_margin_property;

    public Ptr<drm_property> tv_right_margin_property;

    public Ptr<drm_property> tv_top_margin_property;

    public Ptr<drm_property> tv_bottom_margin_property;

    public Ptr<drm_property> tv_brightness_property;

    public Ptr<drm_property> tv_contrast_property;

    public Ptr<drm_property> tv_flicker_reduction_property;

    public Ptr<drm_property> tv_overscan_property;

    public Ptr<drm_property> tv_saturation_property;

    public Ptr<drm_property> tv_hue_property;

    public Ptr<drm_property> scaling_mode_property;

    public Ptr<drm_property> aspect_ratio_property;

    public Ptr<drm_property> content_type_property;

    public Ptr<drm_property> degamma_lut_property;

    public Ptr<drm_property> degamma_lut_size_property;

    public Ptr<drm_property> ctm_property;

    public Ptr<drm_property> gamma_lut_property;

    public Ptr<drm_property> gamma_lut_size_property;

    public Ptr<drm_property> suggested_x_property;

    public Ptr<drm_property> suggested_y_property;

    public Ptr<drm_property> non_desktop_property;

    public Ptr<drm_property> panel_orientation_property;

    public Ptr<drm_property> writeback_fb_id_property;

    public Ptr<drm_property> writeback_pixel_formats_property;

    public Ptr<drm_property> writeback_out_fence_ptr_property;

    public Ptr<drm_property> hdr_output_metadata_property;

    public Ptr<drm_property> content_protection_property;

    public Ptr<drm_property> hdcp_content_type_property;

    public @Unsigned @OriginalName("uint32_t") int preferred_depth;

    public @Unsigned @OriginalName("uint32_t") int prefer_shadow;

    public boolean quirk_addfb_prefer_xbgr_30bpp;

    public boolean quirk_addfb_prefer_host_byte_order;

    public boolean async_page_flip;

    public boolean fb_modifiers_not_supported;

    public boolean normalize_zpos;

    public Ptr<drm_property> modifiers_property;

    public Ptr<drm_property> async_modifiers_property;

    public Ptr<drm_property> size_hints_property;

    public @Unsigned @OriginalName("uint32_t") int cursor_width;

    public @Unsigned @OriginalName("uint32_t") int cursor_height;

    public Ptr<drm_atomic_state> suspend_state;

    public Ptr<drm_mode_config_helper_funcs> helper_private;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_config_helper_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_config_helper_funcs extends Struct {
    public Ptr<?> atomic_commit_tail;

    public Ptr<?> atomic_commit_setup;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_driver"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_driver extends Struct {
    public Ptr<?> load;

    public Ptr<?> open;

    public Ptr<?> postclose;

    public Ptr<?> unload;

    public Ptr<?> release;

    public Ptr<?> master_set;

    public Ptr<?> master_drop;

    public Ptr<?> debugfs_init;

    public Ptr<?> gem_create_object;

    public Ptr<?> prime_handle_to_fd;

    public Ptr<?> prime_fd_to_handle;

    public Ptr<?> gem_prime_import;

    public Ptr<?> gem_prime_import_sg_table;

    public Ptr<?> dumb_create;

    public Ptr<?> dumb_map_offset;

    public Ptr<?> fbdev_probe;

    public Ptr<?> show_fdinfo;

    public int major;

    public int minor;

    public int patchlevel;

    public String name;

    public String desc;

    public @Unsigned int driver_features;

    public Ptr<drm_ioctl_desc> ioctls;

    public int num_ioctls;

    public Ptr<file_operations> fops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_vma_offset_manager"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_vma_offset_manager extends Struct {
    public rwlock_t vm_lock;

    public drm_mm vm_addr_space_mm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_debug_category"
  )
  public enum drm_debug_category implements Enum<drm_debug_category>, TypedEnum<drm_debug_category, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_UT_CORE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_UT_CORE"
    )
    DRM_UT_CORE,

    /**
     * {@code DRM_UT_DRIVER = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_UT_DRIVER"
    )
    DRM_UT_DRIVER,

    /**
     * {@code DRM_UT_KMS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_UT_KMS"
    )
    DRM_UT_KMS,

    /**
     * {@code DRM_UT_PRIME = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DRM_UT_PRIME"
    )
    DRM_UT_PRIME,

    /**
     * {@code DRM_UT_ATOMIC = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_UT_ATOMIC"
    )
    DRM_UT_ATOMIC,

    /**
     * {@code DRM_UT_VBL = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DRM_UT_VBL"
    )
    DRM_UT_VBL,

    /**
     * {@code DRM_UT_STATE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DRM_UT_STATE"
    )
    DRM_UT_STATE,

    /**
     * {@code DRM_UT_LEASE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DRM_UT_LEASE"
    )
    DRM_UT_LEASE,

    /**
     * {@code DRM_UT_DP = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DRM_UT_DP"
    )
    DRM_UT_DP,

    /**
     * {@code DRM_UT_DRMRES = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DRM_UT_DRMRES"
    )
    DRM_UT_DRMRES
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_printer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_printer extends Struct {
    public Ptr<?> printfn;

    public Ptr<?> puts;

    public Ptr<?> arg;

    public Ptr<?> origin;

    public String prefix;

    public line_of_drm_printer line;

    public drm_debug_category category;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mm_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mm_node extends Struct {
    public @Unsigned long color;

    public @Unsigned long start;

    public @Unsigned long size;

    public Ptr<drm_mm> mm;

    public list_head node_list;

    public list_head hole_stack;

    public rb_node rb;

    public rb_node rb_hole_size;

    public rb_node rb_hole_addr;

    public @Unsigned long __subtree_last;

    public @Unsigned long hole_size;

    public @Unsigned long subtree_max_hole;

    public @Unsigned long flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mm"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mm extends Struct {
    public Ptr<?> color_adjust;

    public list_head hole_stack;

    public drm_mm_node head_node;

    public rb_root_cached interval_tree;

    public rb_root_cached holes_size;

    public rb_root holes_addr;

    public @Unsigned long scan_active;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_vma_offset_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_vma_offset_node extends Struct {
    public rwlock_t vm_lock;

    public drm_mm_node vm_node;

    public rb_root vm_files;

    public Ptr<?> driver_private;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_gem_object_status"
  )
  public enum drm_gem_object_status implements Enum<drm_gem_object_status>, TypedEnum<drm_gem_object_status, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_GEM_OBJECT_RESIDENT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_GEM_OBJECT_RESIDENT"
    )
    DRM_GEM_OBJECT_RESIDENT,

    /**
     * {@code DRM_GEM_OBJECT_PURGEABLE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_GEM_OBJECT_PURGEABLE"
    )
    DRM_GEM_OBJECT_PURGEABLE,

    /**
     * {@code DRM_GEM_OBJECT_ACTIVE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_GEM_OBJECT_ACTIVE"
    )
    DRM_GEM_OBJECT_ACTIVE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gem_object_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gem_object_funcs extends Struct {
    public Ptr<?> free;

    public Ptr<?> open;

    public Ptr<?> close;

    public Ptr<?> print_info;

    public Ptr<?> export;

    public Ptr<?> pin;

    public Ptr<?> unpin;

    public Ptr<?> get_sg_table;

    public Ptr<?> vmap;

    public Ptr<?> vunmap;

    public Ptr<?> mmap;

    public Ptr<?> evict;

    public Ptr<?> status;

    public Ptr<?> rss;

    public Ptr<vm_operations_struct> vm_ops;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gem_object"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gem_object extends Struct {
    public kref refcount;

    public @Unsigned int handle_count;

    public Ptr<drm_device> dev;

    public Ptr<file> filp;

    public drm_vma_offset_node vma_node;

    public @Unsigned long size;

    public int name;

    public Ptr<dma_buf> dma_buf;

    public Ptr<dma_buf_attachment> import_attach;

    public Ptr<dma_resv> resv;

    public dma_resv _resv;

    public gpuva_of_drm_gem_object gpuva;

    public Ptr<drm_gem_object_funcs> funcs;

    public list_head lru_node;

    public Ptr<drm_gem_lru> lru;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gem_lru"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gem_lru extends Struct {
    public Ptr<mutex> lock;

    public long count;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_object"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_object extends Struct {
    public @Unsigned @OriginalName("uint32_t") int id;

    public @Unsigned @OriginalName("uint32_t") int type;

    public Ptr<drm_object_properties> properties;

    public kref refcount;

    public Ptr<?> free_cb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_object_properties"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_object_properties extends Struct {
    public int count;

    public Ptr<drm_property> @Size(64) [] properties;

    public @Unsigned @OriginalName("uint64_t") long @Size(64) [] values;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_property"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_property extends Struct {
    public list_head head;

    public drm_mode_object base;

    public @Unsigned @OriginalName("uint32_t") int flags;

    public char @Size(32) [] name;

    public @Unsigned @OriginalName("uint32_t") int num_values;

    public Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> values;

    public Ptr<drm_device> dev;

    public list_head enum_list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_clip_rect"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_clip_rect extends Struct {
    public @Unsigned short x1;

    public @Unsigned short y1;

    public @Unsigned short x2;

    public @Unsigned short y2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_event extends Struct {
    public @Unsigned int type;

    public @Unsigned int length;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_event_vblank"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_event_vblank extends Struct {
    public drm_event base;

    public @Unsigned long user_data;

    public @Unsigned int tv_sec;

    public @Unsigned int tv_usec;

    public @Unsigned int sequence;

    public @Unsigned int crtc_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_event_crtc_sequence"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_event_crtc_sequence extends Struct {
    public drm_event base;

    public @Unsigned long user_data;

    public long time_ns;

    public @Unsigned long sequence;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_mode_subconnector"
  )
  public enum drm_mode_subconnector implements Enum<drm_mode_subconnector>, TypedEnum<drm_mode_subconnector, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_MODE_SUBCONNECTOR_Automatic = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_MODE_SUBCONNECTOR_Automatic"
    )
    DRM_MODE_SUBCONNECTOR_Automatic,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_Unknown = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_MODE_SUBCONNECTOR_Unknown"
    )
    DRM_MODE_SUBCONNECTOR_Unknown,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_VGA = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_MODE_SUBCONNECTOR_VGA"
    )
    DRM_MODE_SUBCONNECTOR_VGA,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_DVID = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DRM_MODE_SUBCONNECTOR_DVID"
    )
    DRM_MODE_SUBCONNECTOR_DVID,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_DVIA = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_MODE_SUBCONNECTOR_DVIA"
    )
    DRM_MODE_SUBCONNECTOR_DVIA,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_Composite = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DRM_MODE_SUBCONNECTOR_Composite"
    )
    DRM_MODE_SUBCONNECTOR_Composite,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_SVIDEO = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DRM_MODE_SUBCONNECTOR_SVIDEO"
    )
    DRM_MODE_SUBCONNECTOR_SVIDEO,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_Component = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DRM_MODE_SUBCONNECTOR_Component"
    )
    DRM_MODE_SUBCONNECTOR_Component,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_SCART = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DRM_MODE_SUBCONNECTOR_SCART"
    )
    DRM_MODE_SUBCONNECTOR_SCART,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_DisplayPort = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DRM_MODE_SUBCONNECTOR_DisplayPort"
    )
    DRM_MODE_SUBCONNECTOR_DisplayPort,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_HDMIA = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DRM_MODE_SUBCONNECTOR_HDMIA"
    )
    DRM_MODE_SUBCONNECTOR_HDMIA,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_Native = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DRM_MODE_SUBCONNECTOR_Native"
    )
    DRM_MODE_SUBCONNECTOR_Native,

    /**
     * {@code DRM_MODE_SUBCONNECTOR_Wireless = 18}
     */
    @EnumMember(
        value = 18L,
        name = "DRM_MODE_SUBCONNECTOR_Wireless"
    )
    DRM_MODE_SUBCONNECTOR_Wireless
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_create_dumb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_create_dumb extends Struct {
    public @Unsigned int height;

    public @Unsigned int width;

    public @Unsigned int bpp;

    public @Unsigned int flags;

    public @Unsigned int handle;

    public @Unsigned int pitch;

    public @Unsigned long size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_rect"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_rect extends Struct {
    public int x1;

    public int y1;

    public int x2;

    public int y2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_property_blob"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_property_blob extends Struct {
    public drm_mode_object base;

    public Ptr<drm_device> dev;

    public list_head head_global;

    public list_head head_file;

    public @Unsigned long length;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_connector_force"
  )
  public enum drm_connector_force implements Enum<drm_connector_force>, TypedEnum<drm_connector_force, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_FORCE_UNSPECIFIED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_FORCE_UNSPECIFIED"
    )
    DRM_FORCE_UNSPECIFIED,

    /**
     * {@code DRM_FORCE_OFF = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_FORCE_OFF"
    )
    DRM_FORCE_OFF,

    /**
     * {@code DRM_FORCE_ON = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_FORCE_ON"
    )
    DRM_FORCE_ON,

    /**
     * {@code DRM_FORCE_ON_DIGITAL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DRM_FORCE_ON_DIGITAL"
    )
    DRM_FORCE_ON_DIGITAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_connector_status"
  )
  public enum drm_connector_status implements Enum<drm_connector_status>, TypedEnum<drm_connector_status, java.lang. @Unsigned Integer> {
    /**
     * {@code connector_status_connected = 1}
     */
    @EnumMember(
        value = 1L,
        name = "connector_status_connected"
    )
    connector_status_connected,

    /**
     * {@code connector_status_disconnected = 2}
     */
    @EnumMember(
        value = 2L,
        name = "connector_status_disconnected"
    )
    connector_status_disconnected,

    /**
     * {@code connector_status_unknown = 3}
     */
    @EnumMember(
        value = 3L,
        name = "connector_status_unknown"
    )
    connector_status_unknown
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_connector_registration_state"
  )
  public enum drm_connector_registration_state implements Enum<drm_connector_registration_state>, TypedEnum<drm_connector_registration_state, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_CONNECTOR_INITIALIZING = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_CONNECTOR_INITIALIZING"
    )
    DRM_CONNECTOR_INITIALIZING,

    /**
     * {@code DRM_CONNECTOR_REGISTERED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_CONNECTOR_REGISTERED"
    )
    DRM_CONNECTOR_REGISTERED,

    /**
     * {@code DRM_CONNECTOR_UNREGISTERED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_CONNECTOR_UNREGISTERED"
    )
    DRM_CONNECTOR_UNREGISTERED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_connector_tv_mode"
  )
  public enum drm_connector_tv_mode implements Enum<drm_connector_tv_mode>, TypedEnum<drm_connector_tv_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_MODE_TV_MODE_NTSC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_MODE_TV_MODE_NTSC"
    )
    DRM_MODE_TV_MODE_NTSC,

    /**
     * {@code DRM_MODE_TV_MODE_NTSC_443 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_MODE_TV_MODE_NTSC_443"
    )
    DRM_MODE_TV_MODE_NTSC_443,

    /**
     * {@code DRM_MODE_TV_MODE_NTSC_J = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_MODE_TV_MODE_NTSC_J"
    )
    DRM_MODE_TV_MODE_NTSC_J,

    /**
     * {@code DRM_MODE_TV_MODE_PAL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DRM_MODE_TV_MODE_PAL"
    )
    DRM_MODE_TV_MODE_PAL,

    /**
     * {@code DRM_MODE_TV_MODE_PAL_M = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_MODE_TV_MODE_PAL_M"
    )
    DRM_MODE_TV_MODE_PAL_M,

    /**
     * {@code DRM_MODE_TV_MODE_PAL_N = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DRM_MODE_TV_MODE_PAL_N"
    )
    DRM_MODE_TV_MODE_PAL_N,

    /**
     * {@code DRM_MODE_TV_MODE_SECAM = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DRM_MODE_TV_MODE_SECAM"
    )
    DRM_MODE_TV_MODE_SECAM,

    /**
     * {@code DRM_MODE_TV_MODE_MONOCHROME = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DRM_MODE_TV_MODE_MONOCHROME"
    )
    DRM_MODE_TV_MODE_MONOCHROME,

    /**
     * {@code DRM_MODE_TV_MODE_MAX = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DRM_MODE_TV_MODE_MAX"
    )
    DRM_MODE_TV_MODE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_scrambling"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_scrambling extends Struct {
    public boolean supported;

    public boolean low_rates;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_scdc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_scdc extends Struct {
    public boolean supported;

    public boolean read_request;

    public drm_scrambling scrambling;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_hdmi_dsc_cap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_hdmi_dsc_cap extends Struct {
    public boolean v_1p2;

    public boolean native_420;

    public boolean all_bpp;

    public char bpc_supported;

    public char max_slices;

    public int clk_per_slice;

    public char max_lanes;

    public char max_frl_rate_per_lane;

    public char total_chunk_kbytes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_hdmi_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_hdmi_info extends Struct {
    public drm_scdc scdc;

    public @Unsigned long @Size(4) [] y420_vdb_modes;

    public @Unsigned long @Size(4) [] y420_cmdb_modes;

    public char y420_dc_modes;

    public char max_frl_rate_per_lane;

    public char max_lanes;

    public drm_hdmi_dsc_cap dsc_cap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_link_status"
  )
  public enum drm_link_status implements Enum<drm_link_status>, TypedEnum<drm_link_status, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_LINK_STATUS_GOOD = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_LINK_STATUS_GOOD"
    )
    DRM_LINK_STATUS_GOOD,

    /**
     * {@code DRM_LINK_STATUS_BAD = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_LINK_STATUS_BAD"
    )
    DRM_LINK_STATUS_BAD
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_panel_orientation"
  )
  public enum drm_panel_orientation implements Enum<drm_panel_orientation>, TypedEnum<drm_panel_orientation, java.lang.Integer> {
    /**
     * {@code DRM_MODE_PANEL_ORIENTATION_UNKNOWN = -1}
     */
    @EnumMember(
        value = -1L,
        name = "DRM_MODE_PANEL_ORIENTATION_UNKNOWN"
    )
    DRM_MODE_PANEL_ORIENTATION_UNKNOWN,

    /**
     * {@code DRM_MODE_PANEL_ORIENTATION_NORMAL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_MODE_PANEL_ORIENTATION_NORMAL"
    )
    DRM_MODE_PANEL_ORIENTATION_NORMAL,

    /**
     * {@code DRM_MODE_PANEL_ORIENTATION_BOTTOM_UP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_MODE_PANEL_ORIENTATION_BOTTOM_UP"
    )
    DRM_MODE_PANEL_ORIENTATION_BOTTOM_UP,

    /**
     * {@code DRM_MODE_PANEL_ORIENTATION_LEFT_UP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_MODE_PANEL_ORIENTATION_LEFT_UP"
    )
    DRM_MODE_PANEL_ORIENTATION_LEFT_UP,

    /**
     * {@code DRM_MODE_PANEL_ORIENTATION_RIGHT_UP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DRM_MODE_PANEL_ORIENTATION_RIGHT_UP"
    )
    DRM_MODE_PANEL_ORIENTATION_RIGHT_UP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_hdmi_broadcast_rgb"
  )
  public enum drm_hdmi_broadcast_rgb implements Enum<drm_hdmi_broadcast_rgb>, TypedEnum<drm_hdmi_broadcast_rgb, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_HDMI_BROADCAST_RGB_AUTO = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_HDMI_BROADCAST_RGB_AUTO"
    )
    DRM_HDMI_BROADCAST_RGB_AUTO,

    /**
     * {@code DRM_HDMI_BROADCAST_RGB_FULL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_HDMI_BROADCAST_RGB_FULL"
    )
    DRM_HDMI_BROADCAST_RGB_FULL,

    /**
     * {@code DRM_HDMI_BROADCAST_RGB_LIMITED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_HDMI_BROADCAST_RGB_LIMITED"
    )
    DRM_HDMI_BROADCAST_RGB_LIMITED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_monitor_range_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_monitor_range_info extends Struct {
    public @Unsigned short min_vfreq;

    public @Unsigned short max_vfreq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_luminance_range_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_luminance_range_info extends Struct {
    public @Unsigned int min_luminance;

    public @Unsigned int max_luminance;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_privacy_screen_status"
  )
  public enum drm_privacy_screen_status implements Enum<drm_privacy_screen_status>, TypedEnum<drm_privacy_screen_status, java.lang. @Unsigned Integer> {
    /**
     * {@code PRIVACY_SCREEN_DISABLED = 0}
     */
    @EnumMember(
        value = 0L,
        name = "PRIVACY_SCREEN_DISABLED"
    )
    PRIVACY_SCREEN_DISABLED,

    /**
     * {@code PRIVACY_SCREEN_ENABLED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "PRIVACY_SCREEN_ENABLED"
    )
    PRIVACY_SCREEN_ENABLED,

    /**
     * {@code PRIVACY_SCREEN_DISABLED_LOCKED = 2}
     */
    @EnumMember(
        value = 2L,
        name = "PRIVACY_SCREEN_DISABLED_LOCKED"
    )
    PRIVACY_SCREEN_DISABLED_LOCKED,

    /**
     * {@code PRIVACY_SCREEN_ENABLED_LOCKED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "PRIVACY_SCREEN_ENABLED_LOCKED"
    )
    PRIVACY_SCREEN_ENABLED_LOCKED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_colorspace"
  )
  public enum drm_colorspace implements Enum<drm_colorspace>, TypedEnum<drm_colorspace, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_MODE_COLORIMETRY_DEFAULT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_MODE_COLORIMETRY_DEFAULT"
    )
    DRM_MODE_COLORIMETRY_DEFAULT,

    /**
     * {@code DRM_MODE_COLORIMETRY_NO_DATA = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_MODE_COLORIMETRY_NO_DATA"
    )
    DRM_MODE_COLORIMETRY_NO_DATA,

    /**
     * {@code DRM_MODE_COLORIMETRY_SMPTE_170M_YCC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_MODE_COLORIMETRY_SMPTE_170M_YCC"
    )
    DRM_MODE_COLORIMETRY_SMPTE_170M_YCC,

    /**
     * {@code DRM_MODE_COLORIMETRY_BT709_YCC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_MODE_COLORIMETRY_BT709_YCC"
    )
    DRM_MODE_COLORIMETRY_BT709_YCC,

    /**
     * {@code DRM_MODE_COLORIMETRY_XVYCC_601 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DRM_MODE_COLORIMETRY_XVYCC_601"
    )
    DRM_MODE_COLORIMETRY_XVYCC_601,

    /**
     * {@code DRM_MODE_COLORIMETRY_XVYCC_709 = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_MODE_COLORIMETRY_XVYCC_709"
    )
    DRM_MODE_COLORIMETRY_XVYCC_709,

    /**
     * {@code DRM_MODE_COLORIMETRY_SYCC_601 = 5}
     */
    @EnumMember(
        value = 5L,
        name = "DRM_MODE_COLORIMETRY_SYCC_601"
    )
    DRM_MODE_COLORIMETRY_SYCC_601,

    /**
     * {@code DRM_MODE_COLORIMETRY_OPYCC_601 = 6}
     */
    @EnumMember(
        value = 6L,
        name = "DRM_MODE_COLORIMETRY_OPYCC_601"
    )
    DRM_MODE_COLORIMETRY_OPYCC_601,

    /**
     * {@code DRM_MODE_COLORIMETRY_OPRGB = 7}
     */
    @EnumMember(
        value = 7L,
        name = "DRM_MODE_COLORIMETRY_OPRGB"
    )
    DRM_MODE_COLORIMETRY_OPRGB,

    /**
     * {@code DRM_MODE_COLORIMETRY_BT2020_CYCC = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DRM_MODE_COLORIMETRY_BT2020_CYCC"
    )
    DRM_MODE_COLORIMETRY_BT2020_CYCC,

    /**
     * {@code DRM_MODE_COLORIMETRY_BT2020_RGB = 9}
     */
    @EnumMember(
        value = 9L,
        name = "DRM_MODE_COLORIMETRY_BT2020_RGB"
    )
    DRM_MODE_COLORIMETRY_BT2020_RGB,

    /**
     * {@code DRM_MODE_COLORIMETRY_BT2020_YCC = 10}
     */
    @EnumMember(
        value = 10L,
        name = "DRM_MODE_COLORIMETRY_BT2020_YCC"
    )
    DRM_MODE_COLORIMETRY_BT2020_YCC,

    /**
     * {@code DRM_MODE_COLORIMETRY_DCI_P3_RGB_D65 = 11}
     */
    @EnumMember(
        value = 11L,
        name = "DRM_MODE_COLORIMETRY_DCI_P3_RGB_D65"
    )
    DRM_MODE_COLORIMETRY_DCI_P3_RGB_D65,

    /**
     * {@code DRM_MODE_COLORIMETRY_DCI_P3_RGB_THEATER = 12}
     */
    @EnumMember(
        value = 12L,
        name = "DRM_MODE_COLORIMETRY_DCI_P3_RGB_THEATER"
    )
    DRM_MODE_COLORIMETRY_DCI_P3_RGB_THEATER,

    /**
     * {@code DRM_MODE_COLORIMETRY_RGB_WIDE_FIXED = 13}
     */
    @EnumMember(
        value = 13L,
        name = "DRM_MODE_COLORIMETRY_RGB_WIDE_FIXED"
    )
    DRM_MODE_COLORIMETRY_RGB_WIDE_FIXED,

    /**
     * {@code DRM_MODE_COLORIMETRY_RGB_WIDE_FLOAT = 14}
     */
    @EnumMember(
        value = 14L,
        name = "DRM_MODE_COLORIMETRY_RGB_WIDE_FLOAT"
    )
    DRM_MODE_COLORIMETRY_RGB_WIDE_FLOAT,

    /**
     * {@code DRM_MODE_COLORIMETRY_BT601_YCC = 15}
     */
    @EnumMember(
        value = 15L,
        name = "DRM_MODE_COLORIMETRY_BT601_YCC"
    )
    DRM_MODE_COLORIMETRY_BT601_YCC,

    /**
     * {@code DRM_MODE_COLORIMETRY_COUNT = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DRM_MODE_COLORIMETRY_COUNT"
    )
    DRM_MODE_COLORIMETRY_COUNT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_display_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_display_info extends Struct {
    public @Unsigned int width_mm;

    public @Unsigned int height_mm;

    public @Unsigned int bpc;

    public subpixel_order subpixel_order;

    public int panel_orientation;

    public @Unsigned int color_formats;

    public Ptr<java.lang. @Unsigned Integer> bus_formats;

    public @Unsigned int num_bus_formats;

    public @Unsigned int bus_flags;

    public int max_tmds_clock;

    public boolean dvi_dual;

    public boolean is_hdmi;

    public boolean has_audio;

    public boolean has_hdmi_infoframe;

    public boolean rgb_quant_range_selectable;

    public char edid_hdmi_rgb444_dc_modes;

    public char edid_hdmi_ycbcr444_dc_modes;

    public char cea_rev;

    public drm_hdmi_info hdmi;

    public hdr_sink_metadata hdr_sink_metadata;

    public boolean non_desktop;

    public drm_monitor_range_info monitor_range;

    public drm_luminance_range_info luminance_range;

    public char mso_stream_count;

    public char mso_pixel_overlap;

    public @Unsigned int max_dsc_bpp;

    public Ptr<java.lang.Character> vics;

    public int vics_len;

    public @Unsigned int quirks;

    public @Unsigned short source_physical_address;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_tv_margins"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_tv_margins extends Struct {
    public @Unsigned int bottom;

    public @Unsigned int left;

    public @Unsigned int right;

    public @Unsigned int top;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_tv_connector_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_tv_connector_state extends Struct {
    public drm_mode_subconnector select_subconnector;

    public drm_mode_subconnector subconnector;

    public drm_connector_tv_margins margins;

    public @Unsigned int legacy_mode;

    public @Unsigned int mode;

    public @Unsigned int brightness;

    public @Unsigned int contrast;

    public @Unsigned int flicker_reduction;

    public @Unsigned int overscan;

    public @Unsigned int saturation;

    public @Unsigned int hue;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_hdmi_infoframe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_hdmi_infoframe extends Struct {
    public hdmi_infoframe data;

    public boolean set;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_hdmi_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_hdmi_state extends Struct {
    public drm_hdmi_broadcast_rgb broadcast_rgb;

    public infoframes_of_drm_connector_hdmi_state infoframes;

    public boolean is_limited_range;

    public @Unsigned int output_bpc;

    public hdmi_colorspace output_format;

    public @Unsigned long tmds_char_rate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_state extends Struct {
    public Ptr<drm_connector> connector;

    public Ptr<drm_crtc> crtc;

    public Ptr<drm_encoder> best_encoder;

    public drm_link_status link_status;

    public Ptr<drm_atomic_state> state;

    public Ptr<drm_crtc_commit> commit;

    public drm_tv_connector_state tv;

    public boolean self_refresh_aware;

    public hdmi_picture_aspect picture_aspect_ratio;

    public @Unsigned int content_type;

    public @Unsigned int hdcp_content_type;

    public @Unsigned int scaling_mode;

    public @Unsigned int content_protection;

    public drm_colorspace colorspace;

    public Ptr<drm_writeback_job> writeback_job;

    public char max_requested_bpc;

    public char max_bpc;

    public drm_privacy_screen_status privacy_screen_sw_state;

    public Ptr<drm_property_blob> hdr_output_metadata;

    public drm_connector_hdmi_state hdmi;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector extends Struct {
    public Ptr<drm_device> dev;

    public Ptr<device> kdev;

    public Ptr<device_attribute> attr;

    public Ptr<fwnode_handle> fwnode;

    public list_head head;

    public list_head global_connector_list_entry;

    public drm_mode_object base;

    public String name;

    public mutex mutex;

    public @Unsigned int index;

    public int connector_type;

    public int connector_type_id;

    public boolean interlace_allowed;

    public boolean doublescan_allowed;

    public boolean stereo_allowed;

    public boolean ycbcr_420_allowed;

    public drm_connector_registration_state registration_state;

    public list_head modes;

    public drm_connector_status status;

    public list_head probed_modes;

    public drm_display_info display_info;

    public Ptr<drm_connector_funcs> funcs;

    public Ptr<drm_property_blob> edid_blob_ptr;

    public drm_object_properties properties;

    public Ptr<drm_property> scaling_mode_property;

    public Ptr<drm_property> vrr_capable_property;

    public Ptr<drm_property> colorspace_property;

    public Ptr<drm_property_blob> path_blob_ptr;

    public @Unsigned int max_bpc;

    public Ptr<drm_property> max_bpc_property;

    public Ptr<drm_privacy_screen> privacy_screen;

    public notifier_block privacy_screen_notifier;

    public Ptr<drm_property> privacy_screen_sw_state_property;

    public Ptr<drm_property> privacy_screen_hw_state_property;

    public Ptr<drm_property> broadcast_rgb_property;

    public @OriginalName("uint8_t") char polled;

    public int dpms;

    public Ptr<drm_connector_helper_funcs> helper_private;

    public drm_cmdline_mode cmdline_mode;

    public drm_connector_force force;

    public Ptr<drm_edid> edid_override;

    public mutex edid_override_mutex;

    public @Unsigned long epoch_counter;

    public @Unsigned int possible_encoders;

    public Ptr<drm_encoder> encoder;

    public @OriginalName("uint8_t") char @Size(128) [] eld;

    public mutex eld_mutex;

    public boolean @Size(2) [] latency_present;

    public int @Size(2) [] video_latency;

    public int @Size(2) [] audio_latency;

    public Ptr<i2c_adapter> ddc;

    public int null_edid_counter;

    public @Unsigned int bad_edid_counter;

    public boolean edid_corrupt;

    public char real_edid_checksum;

    public Ptr<dentry> debugfs_entry;

    public Ptr<drm_connector_state> state;

    public Ptr<drm_property_blob> tile_blob_ptr;

    public boolean has_tile;

    public Ptr<drm_tile_group> tile_group;

    public boolean tile_is_single_monitor;

    public @OriginalName("uint8_t") char num_h_tile;

    public @OriginalName("uint8_t") char num_v_tile;

    public @OriginalName("uint8_t") char tile_h_loc;

    public @OriginalName("uint8_t") char tile_v_loc;

    public @Unsigned @OriginalName("uint16_t") short tile_h_size;

    public @Unsigned @OriginalName("uint16_t") short tile_v_size;

    public llist_node free_node;

    public drm_connector_hdmi hdmi;

    public drm_connector_hdmi_audio hdmi_audio;

    public drm_connector_cec cec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_crtc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_crtc extends Struct {
    public Ptr<drm_device> dev;

    public Ptr<device_node> port;

    public list_head head;

    public String name;

    public drm_modeset_lock mutex;

    public drm_mode_object base;

    public Ptr<drm_plane> primary;

    public Ptr<drm_plane> cursor;

    public @Unsigned int index;

    public int cursor_x;

    public int cursor_y;

    public boolean enabled;

    public drm_display_mode mode;

    public drm_display_mode hwmode;

    public int x;

    public int y;

    public Ptr<drm_crtc_funcs> funcs;

    public @Unsigned @OriginalName("uint32_t") int gamma_size;

    public Ptr<java.lang. @Unsigned @OriginalName("uint16_t") Short> gamma_store;

    public Ptr<drm_crtc_helper_funcs> helper_private;

    public drm_object_properties properties;

    public Ptr<drm_property> scaling_filter_property;

    public Ptr<drm_crtc_state> state;

    public list_head commit_list;

    public @OriginalName("spinlock_t") spinlock commit_lock;

    public Ptr<dentry> debugfs_entry;

    public drm_crtc_crc crc;

    public @Unsigned int fence_context;

    public @OriginalName("spinlock_t") spinlock fence_lock;

    public @Unsigned long fence_seqno;

    public char @Size(32) [] timeline_name;

    public Ptr<drm_self_refresh_data> self_refresh_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_encoder"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_encoder extends Struct {
    public Ptr<drm_device> dev;

    public list_head head;

    public drm_mode_object base;

    public String name;

    public int encoder_type;

    public @Unsigned int index;

    public @Unsigned @OriginalName("uint32_t") int possible_crtcs;

    public @Unsigned @OriginalName("uint32_t") int possible_clones;

    public Ptr<drm_crtc> crtc;

    public list_head bridge_chain;

    public Ptr<drm_encoder_funcs> funcs;

    public Ptr<drm_encoder_helper_funcs> helper_private;

    public Ptr<dentry> debugfs_entry;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_atomic_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_atomic_state extends Struct {
    public kref ref;

    public Ptr<drm_device> dev;

    public boolean allow_modeset;

    public boolean legacy_cursor_update;

    public boolean async_update;

    public boolean duplicated;

    public Ptr<__drm_planes_state> planes;

    public Ptr<__drm_crtcs_state> crtcs;

    public int num_connector;

    public Ptr<__drm_connnectors_state> connectors;

    public int num_private_objs;

    public Ptr<__drm_private_objs_state> private_objs;

    public Ptr<drm_modeset_acquire_ctx> acquire_ctx;

    public Ptr<drm_crtc_commit> fake_commit;

    public work_struct commit_work;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_crtc_commit"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_crtc_commit extends Struct {
    public Ptr<drm_crtc> crtc;

    public kref ref;

    public completion flip_done;

    public completion hw_done;

    public completion cleanup_done;

    public list_head commit_entry;

    public Ptr<drm_pending_vblank_event> event;

    public boolean abort_completion;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_writeback_job"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_writeback_job extends Struct {
    public Ptr<drm_writeback_connector> connector;

    public boolean prepared;

    public work_struct cleanup_work;

    public list_head list_entry;

    public Ptr<drm_framebuffer> fb;

    public Ptr<dma_fence> out_fence;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_hdmi_audio_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_hdmi_audio_funcs extends Struct {
    public Ptr<?> startup;

    public Ptr<?> prepare;

    public Ptr<?> shutdown;

    public Ptr<?> mute_stream;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_cec_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_cec_funcs extends Struct {
    public Ptr<?> phys_addr_invalidate;

    public Ptr<?> phys_addr_set;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_hdmi_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_hdmi_funcs extends Struct {
    public Ptr<?> tmds_char_rate_valid;

    public Ptr<?> clear_infoframe;

    public Ptr<?> write_infoframe;

    public Ptr<?> read_edid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_mode_status"
  )
  public enum drm_mode_status implements Enum<drm_mode_status>, TypedEnum<drm_mode_status, java.lang.Integer> {
    /**
     * {@code MODE_OK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "MODE_OK"
    )
    MODE_OK,

    /**
     * {@code MODE_HSYNC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "MODE_HSYNC"
    )
    MODE_HSYNC,

    /**
     * {@code MODE_VSYNC = 2}
     */
    @EnumMember(
        value = 2L,
        name = "MODE_VSYNC"
    )
    MODE_VSYNC,

    /**
     * {@code MODE_H_ILLEGAL = 3}
     */
    @EnumMember(
        value = 3L,
        name = "MODE_H_ILLEGAL"
    )
    MODE_H_ILLEGAL,

    /**
     * {@code MODE_V_ILLEGAL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "MODE_V_ILLEGAL"
    )
    MODE_V_ILLEGAL,

    /**
     * {@code MODE_BAD_WIDTH = 5}
     */
    @EnumMember(
        value = 5L,
        name = "MODE_BAD_WIDTH"
    )
    MODE_BAD_WIDTH,

    /**
     * {@code MODE_NOMODE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "MODE_NOMODE"
    )
    MODE_NOMODE,

    /**
     * {@code MODE_NO_INTERLACE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "MODE_NO_INTERLACE"
    )
    MODE_NO_INTERLACE,

    /**
     * {@code MODE_NO_DBLESCAN = 8}
     */
    @EnumMember(
        value = 8L,
        name = "MODE_NO_DBLESCAN"
    )
    MODE_NO_DBLESCAN,

    /**
     * {@code MODE_NO_VSCAN = 9}
     */
    @EnumMember(
        value = 9L,
        name = "MODE_NO_VSCAN"
    )
    MODE_NO_VSCAN,

    /**
     * {@code MODE_MEM = 10}
     */
    @EnumMember(
        value = 10L,
        name = "MODE_MEM"
    )
    MODE_MEM,

    /**
     * {@code MODE_VIRTUAL_X = 11}
     */
    @EnumMember(
        value = 11L,
        name = "MODE_VIRTUAL_X"
    )
    MODE_VIRTUAL_X,

    /**
     * {@code MODE_VIRTUAL_Y = 12}
     */
    @EnumMember(
        value = 12L,
        name = "MODE_VIRTUAL_Y"
    )
    MODE_VIRTUAL_Y,

    /**
     * {@code MODE_MEM_VIRT = 13}
     */
    @EnumMember(
        value = 13L,
        name = "MODE_MEM_VIRT"
    )
    MODE_MEM_VIRT,

    /**
     * {@code MODE_NOCLOCK = 14}
     */
    @EnumMember(
        value = 14L,
        name = "MODE_NOCLOCK"
    )
    MODE_NOCLOCK,

    /**
     * {@code MODE_CLOCK_HIGH = 15}
     */
    @EnumMember(
        value = 15L,
        name = "MODE_CLOCK_HIGH"
    )
    MODE_CLOCK_HIGH,

    /**
     * {@code MODE_CLOCK_LOW = 16}
     */
    @EnumMember(
        value = 16L,
        name = "MODE_CLOCK_LOW"
    )
    MODE_CLOCK_LOW,

    /**
     * {@code MODE_CLOCK_RANGE = 17}
     */
    @EnumMember(
        value = 17L,
        name = "MODE_CLOCK_RANGE"
    )
    MODE_CLOCK_RANGE,

    /**
     * {@code MODE_BAD_HVALUE = 18}
     */
    @EnumMember(
        value = 18L,
        name = "MODE_BAD_HVALUE"
    )
    MODE_BAD_HVALUE,

    /**
     * {@code MODE_BAD_VVALUE = 19}
     */
    @EnumMember(
        value = 19L,
        name = "MODE_BAD_VVALUE"
    )
    MODE_BAD_VVALUE,

    /**
     * {@code MODE_BAD_VSCAN = 20}
     */
    @EnumMember(
        value = 20L,
        name = "MODE_BAD_VSCAN"
    )
    MODE_BAD_VSCAN,

    /**
     * {@code MODE_HSYNC_NARROW = 21}
     */
    @EnumMember(
        value = 21L,
        name = "MODE_HSYNC_NARROW"
    )
    MODE_HSYNC_NARROW,

    /**
     * {@code MODE_HSYNC_WIDE = 22}
     */
    @EnumMember(
        value = 22L,
        name = "MODE_HSYNC_WIDE"
    )
    MODE_HSYNC_WIDE,

    /**
     * {@code MODE_HBLANK_NARROW = 23}
     */
    @EnumMember(
        value = 23L,
        name = "MODE_HBLANK_NARROW"
    )
    MODE_HBLANK_NARROW,

    /**
     * {@code MODE_HBLANK_WIDE = 24}
     */
    @EnumMember(
        value = 24L,
        name = "MODE_HBLANK_WIDE"
    )
    MODE_HBLANK_WIDE,

    /**
     * {@code MODE_VSYNC_NARROW = 25}
     */
    @EnumMember(
        value = 25L,
        name = "MODE_VSYNC_NARROW"
    )
    MODE_VSYNC_NARROW,

    /**
     * {@code MODE_VSYNC_WIDE = 26}
     */
    @EnumMember(
        value = 26L,
        name = "MODE_VSYNC_WIDE"
    )
    MODE_VSYNC_WIDE,

    /**
     * {@code MODE_VBLANK_NARROW = 27}
     */
    @EnumMember(
        value = 27L,
        name = "MODE_VBLANK_NARROW"
    )
    MODE_VBLANK_NARROW,

    /**
     * {@code MODE_VBLANK_WIDE = 28}
     */
    @EnumMember(
        value = 28L,
        name = "MODE_VBLANK_WIDE"
    )
    MODE_VBLANK_WIDE,

    /**
     * {@code MODE_PANEL = 29}
     */
    @EnumMember(
        value = 29L,
        name = "MODE_PANEL"
    )
    MODE_PANEL,

    /**
     * {@code MODE_INTERLACE_WIDTH = 30}
     */
    @EnumMember(
        value = 30L,
        name = "MODE_INTERLACE_WIDTH"
    )
    MODE_INTERLACE_WIDTH,

    /**
     * {@code MODE_ONE_WIDTH = 31}
     */
    @EnumMember(
        value = 31L,
        name = "MODE_ONE_WIDTH"
    )
    MODE_ONE_WIDTH,

    /**
     * {@code MODE_ONE_HEIGHT = 32}
     */
    @EnumMember(
        value = 32L,
        name = "MODE_ONE_HEIGHT"
    )
    MODE_ONE_HEIGHT,

    /**
     * {@code MODE_ONE_SIZE = 33}
     */
    @EnumMember(
        value = 33L,
        name = "MODE_ONE_SIZE"
    )
    MODE_ONE_SIZE,

    /**
     * {@code MODE_NO_REDUCED = 34}
     */
    @EnumMember(
        value = 34L,
        name = "MODE_NO_REDUCED"
    )
    MODE_NO_REDUCED,

    /**
     * {@code MODE_NO_STEREO = 35}
     */
    @EnumMember(
        value = 35L,
        name = "MODE_NO_STEREO"
    )
    MODE_NO_STEREO,

    /**
     * {@code MODE_NO_420 = 36}
     */
    @EnumMember(
        value = 36L,
        name = "MODE_NO_420"
    )
    MODE_NO_420,

    /**
     * {@code MODE_STALE = -3}
     */
    @EnumMember(
        value = -3L,
        name = "MODE_STALE"
    )
    MODE_STALE,

    /**
     * {@code MODE_BAD = -2}
     */
    @EnumMember(
        value = -2L,
        name = "MODE_BAD"
    )
    MODE_BAD,

    /**
     * {@code MODE_ERROR = -1}
     */
    @EnumMember(
        value = -1L,
        name = "MODE_ERROR"
    )
    MODE_ERROR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_edid"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_edid extends Struct {
    public @Unsigned long size;

    public Ptr<edid> edid;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_funcs extends Struct {
    public Ptr<?> dpms;

    public Ptr<?> reset;

    public Ptr<?> detect;

    public Ptr<?> force;

    public Ptr<?> fill_modes;

    public Ptr<?> set_property;

    public Ptr<?> late_register;

    public Ptr<?> early_unregister;

    public Ptr<?> destroy;

    public Ptr<?> atomic_duplicate_state;

    public Ptr<?> atomic_destroy_state;

    public Ptr<?> atomic_set_property;

    public Ptr<?> atomic_get_property;

    public Ptr<?> atomic_print_state;

    public Ptr<?> oob_hotplug_event;

    public Ptr<?> debugfs_init;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_cmdline_mode"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_cmdline_mode extends Struct {
    public char @Size(32) [] name;

    public boolean specified;

    public boolean refresh_specified;

    public boolean bpp_specified;

    public @Unsigned int pixel_clock;

    public int xres;

    public int yres;

    public int bpp;

    public int refresh;

    public boolean rb;

    public boolean interlace;

    public boolean cvt;

    public boolean margins;

    public drm_connector_force force;

    public @Unsigned int rotation_reflection;

    public drm_panel_orientation panel_orientation;

    public drm_connector_tv_margins tv_margins;

    public drm_connector_tv_mode tv_mode;

    public boolean tv_mode_specified;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_hdmi_audio"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_hdmi_audio extends Struct {
    public Ptr<drm_connector_hdmi_audio_funcs> funcs;

    public Ptr<platform_device> codec_pdev;

    public mutex lock;

    public Ptr<?> plugged_cb;

    public Ptr<device> plugged_cb_dev;

    public boolean last_state;

    public int dai_port;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_hdmi"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_hdmi extends Struct {
    public char @Size(8) [] vendor;

    public char @Size(16) [] product;

    public @Unsigned long supported_formats;

    public Ptr<drm_connector_hdmi_funcs> funcs;

    public infoframes_of_drm_connector_hdmi infoframes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_cec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_cec extends Struct {
    public mutex mutex;

    public Ptr<drm_connector_cec_funcs> funcs;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_helper_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_helper_funcs extends Struct {
    public Ptr<?> get_modes;

    public Ptr<?> detect_ctx;

    public Ptr<?> mode_valid;

    public Ptr<?> mode_valid_ctx;

    public Ptr<?> best_encoder;

    public Ptr<?> atomic_best_encoder;

    public Ptr<?> atomic_check;

    public Ptr<?> atomic_commit;

    public Ptr<?> prepare_writeback_job;

    public Ptr<?> cleanup_writeback_job;

    public Ptr<?> enable_hpd;

    public Ptr<?> disable_hpd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_tile_group"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_tile_group extends Struct {
    public kref refcount;

    public Ptr<drm_device> dev;

    public int id;

    public char @Size(8) [] group_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_connector_list_iter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_connector_list_iter extends Struct {
    public Ptr<drm_device> dev;

    public Ptr<drm_connector> conn;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_framebuffer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_framebuffer extends Struct {
    public Ptr<drm_device> dev;

    public list_head head;

    public drm_mode_object base;

    public char @Size(16) [] comm;

    public Ptr<drm_format_info> format;

    public Ptr<drm_framebuffer_funcs> funcs;

    public @Unsigned int @Size(4) [] pitches;

    public @Unsigned int @Size(4) [] offsets;

    public @Unsigned @OriginalName("uint64_t") long modifier;

    public @Unsigned int width;

    public @Unsigned int height;

    public int flags;

    public @Unsigned int internal_flags;

    public list_head filp_head;

    public Ptr<drm_gem_object> @Size(4) [] obj;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_file"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_file extends Struct {
    public boolean authenticated;

    public boolean stereo_allowed;

    public boolean universal_planes;

    public boolean atomic;

    public boolean aspect_ratio_allowed;

    public boolean writeback_connectors;

    public boolean was_master;

    public boolean is_master;

    public boolean supports_virtualized_cursor_plane;

    public Ptr<drm_master> master;

    public @OriginalName("spinlock_t") spinlock master_lookup_lock;

    public Ptr<pid> pid;

    public @Unsigned long client_id;

    public @Unsigned @OriginalName("drm_magic_t") int magic;

    public list_head lhead;

    public Ptr<drm_minor> minor;

    public idr object_idr;

    public @OriginalName("spinlock_t") spinlock table_lock;

    public idr syncobj_idr;

    public @OriginalName("spinlock_t") spinlock syncobj_table_lock;

    public Ptr<file> filp;

    public Ptr<?> driver_priv;

    public list_head fbs;

    public mutex fbs_lock;

    public list_head blobs;

    public @OriginalName("wait_queue_head_t") wait_queue_head event_wait;

    public list_head pending_event_list;

    public list_head event_list;

    public int event_space;

    public mutex event_read_lock;

    public drm_prime_file_private prime;

    public String client_name;

    public mutex client_name_lock;

    public Ptr<dentry> debugfs_client;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_minor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_minor extends Struct {
    public int index;

    public int type;

    public Ptr<device> kdev;

    public Ptr<drm_device> dev;

    public Ptr<dentry> debugfs_symlink;

    public Ptr<dentry> debugfs_root;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_vblank_crtc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_vblank_crtc extends Struct {
    public Ptr<drm_device> dev;

    public @OriginalName("wait_queue_head_t") wait_queue_head queue;

    public timer_list disable_timer;

    public seqlock_t seqlock;

    public atomic64_t count;

    public @OriginalName("ktime_t") long time;

    public atomic_t refcount;

    public @Unsigned int last;

    public @Unsigned int max_vblank_count;

    public @Unsigned int inmodeset;

    public @Unsigned int pipe;

    public int framedur_ns;

    public int linedur_ns;

    public drm_display_mode hwmode;

    public drm_vblank_crtc_config config;

    public boolean enabled;

    public Ptr<kthread_worker> worker;

    public list_head pending_work;

    public @OriginalName("wait_queue_head_t") wait_queue_head work_wait_queue;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_color_encoding"
  )
  public enum drm_color_encoding implements Enum<drm_color_encoding>, TypedEnum<drm_color_encoding, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_COLOR_YCBCR_BT601 = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_COLOR_YCBCR_BT601"
    )
    DRM_COLOR_YCBCR_BT601,

    /**
     * {@code DRM_COLOR_YCBCR_BT709 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_COLOR_YCBCR_BT709"
    )
    DRM_COLOR_YCBCR_BT709,

    /**
     * {@code DRM_COLOR_YCBCR_BT2020 = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_COLOR_YCBCR_BT2020"
    )
    DRM_COLOR_YCBCR_BT2020,

    /**
     * {@code DRM_COLOR_ENCODING_MAX = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DRM_COLOR_ENCODING_MAX"
    )
    DRM_COLOR_ENCODING_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_color_range"
  )
  public enum drm_color_range implements Enum<drm_color_range>, TypedEnum<drm_color_range, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_COLOR_YCBCR_LIMITED_RANGE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_COLOR_YCBCR_LIMITED_RANGE"
    )
    DRM_COLOR_YCBCR_LIMITED_RANGE,

    /**
     * {@code DRM_COLOR_YCBCR_FULL_RANGE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_COLOR_YCBCR_FULL_RANGE"
    )
    DRM_COLOR_YCBCR_FULL_RANGE,

    /**
     * {@code DRM_COLOR_RANGE_MAX = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_COLOR_RANGE_MAX"
    )
    DRM_COLOR_RANGE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_rect"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_rect extends Struct {
    public int x1;

    public int y1;

    public int x2;

    public int y2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_scaling_filter"
  )
  public enum drm_scaling_filter implements Enum<drm_scaling_filter>, TypedEnum<drm_scaling_filter, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_SCALING_FILTER_DEFAULT = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_SCALING_FILTER_DEFAULT"
    )
    DRM_SCALING_FILTER_DEFAULT,

    /**
     * {@code DRM_SCALING_FILTER_NEAREST_NEIGHBOR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_SCALING_FILTER_NEAREST_NEIGHBOR"
    )
    DRM_SCALING_FILTER_NEAREST_NEIGHBOR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_plane_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_plane_state extends Struct {
    public Ptr<drm_plane> plane;

    public Ptr<drm_crtc> crtc;

    public Ptr<drm_framebuffer> fb;

    public Ptr<dma_fence> fence;

    public @OriginalName("int32_t") int crtc_x;

    public @OriginalName("int32_t") int crtc_y;

    public @Unsigned @OriginalName("uint32_t") int crtc_w;

    public @Unsigned @OriginalName("uint32_t") int crtc_h;

    public @Unsigned @OriginalName("uint32_t") int src_x;

    public @Unsigned @OriginalName("uint32_t") int src_y;

    public @Unsigned @OriginalName("uint32_t") int src_h;

    public @Unsigned @OriginalName("uint32_t") int src_w;

    public @OriginalName("int32_t") int hotspot_x;

    public @OriginalName("int32_t") int hotspot_y;

    public @Unsigned short alpha;

    public @Unsigned @OriginalName("uint16_t") short pixel_blend_mode;

    public @Unsigned int rotation;

    public @Unsigned int zpos;

    public @Unsigned int normalized_zpos;

    public drm_color_encoding color_encoding;

    public drm_color_range color_range;

    public Ptr<drm_property_blob> fb_damage_clips;

    public boolean ignore_damage_clips;

    public drm_rect src;

    public drm_rect dst;

    public boolean visible;

    public drm_scaling_filter scaling_filter;

    public Ptr<drm_crtc_commit> commit;

    public Ptr<drm_atomic_state> state;

    public boolean color_mgmt_changed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_plane"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_plane extends Struct {
    public Ptr<drm_device> dev;

    public list_head head;

    public String name;

    public drm_modeset_lock mutex;

    public drm_mode_object base;

    public @Unsigned @OriginalName("uint32_t") int possible_crtcs;

    public Ptr<java.lang. @Unsigned @OriginalName("uint32_t") Integer> format_types;

    public @Unsigned int format_count;

    public boolean format_default;

    public Ptr<java.lang. @Unsigned @OriginalName("uint64_t") Long> modifiers;

    public @Unsigned int modifier_count;

    public Ptr<drm_crtc> crtc;

    public Ptr<drm_framebuffer> fb;

    public Ptr<drm_framebuffer> old_fb;

    public Ptr<drm_plane_funcs> funcs;

    public drm_object_properties properties;

    public drm_plane_type type;

    public @Unsigned int index;

    public Ptr<drm_plane_helper_funcs> helper_private;

    public Ptr<drm_plane_state> state;

    public Ptr<drm_property> alpha_property;

    public Ptr<drm_property> zpos_property;

    public Ptr<drm_property> rotation_property;

    public Ptr<drm_property> blend_mode_property;

    public Ptr<drm_property> color_encoding_property;

    public Ptr<drm_property> color_range_property;

    public Ptr<drm_property> scaling_filter_property;

    public Ptr<drm_property> hotspot_x_property;

    public Ptr<drm_property> hotspot_y_property;

    public kmsg_dumper kmsg_panic;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_plane_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_plane_funcs extends Struct {
    public Ptr<?> update_plane;

    public Ptr<?> disable_plane;

    public Ptr<?> destroy;

    public Ptr<?> reset;

    public Ptr<?> set_property;

    public Ptr<?> atomic_duplicate_state;

    public Ptr<?> atomic_destroy_state;

    public Ptr<?> atomic_set_property;

    public Ptr<?> atomic_get_property;

    public Ptr<?> late_register;

    public Ptr<?> early_unregister;

    public Ptr<?> atomic_print_state;

    public Ptr<?> format_mod_supported;

    public Ptr<?> format_mod_supported_async;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_plane_type"
  )
  public enum drm_plane_type implements Enum<drm_plane_type>, TypedEnum<drm_plane_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_PLANE_TYPE_OVERLAY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_PLANE_TYPE_OVERLAY"
    )
    DRM_PLANE_TYPE_OVERLAY,

    /**
     * {@code DRM_PLANE_TYPE_PRIMARY = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_PLANE_TYPE_PRIMARY"
    )
    DRM_PLANE_TYPE_PRIMARY,

    /**
     * {@code DRM_PLANE_TYPE_CURSOR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_PLANE_TYPE_CURSOR"
    )
    DRM_PLANE_TYPE_CURSOR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_plane_helper_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_plane_helper_funcs extends Struct {
    public Ptr<?> prepare_fb;

    public Ptr<?> cleanup_fb;

    public Ptr<?> begin_fb_access;

    public Ptr<?> end_fb_access;

    public Ptr<?> atomic_check;

    public Ptr<?> atomic_update;

    public Ptr<?> atomic_enable;

    public Ptr<?> atomic_disable;

    public Ptr<?> atomic_async_check;

    public Ptr<?> atomic_async_update;

    public Ptr<?> get_scanout_buffer;

    public Ptr<?> panic_flush;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_crtc_crc_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_crtc_crc_entry extends Struct {
    public boolean has_frame_counter;

    public @Unsigned @OriginalName("uint32_t") int frame;

    public @Unsigned @OriginalName("uint32_t") int @Size(10) [] crcs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_crtc_crc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_crtc_crc extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public String source;

    public boolean opened;

    public boolean overflow;

    public Ptr<drm_crtc_crc_entry> entries;

    public int head;

    public int tail;

    public @Unsigned long values_cnt;

    public @OriginalName("wait_queue_head_t") wait_queue_head wq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_crtc_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_crtc_state extends Struct {
    public Ptr<drm_crtc> crtc;

    public boolean enable;

    public boolean active;

    public boolean planes_changed;

    public boolean mode_changed;

    public boolean active_changed;

    public boolean connectors_changed;

    public boolean zpos_changed;

    public boolean color_mgmt_changed;

    public boolean no_vblank;

    public @Unsigned int plane_mask;

    public @Unsigned int connector_mask;

    public @Unsigned int encoder_mask;

    public drm_display_mode adjusted_mode;

    public drm_display_mode mode;

    public Ptr<drm_property_blob> mode_blob;

    public Ptr<drm_property_blob> degamma_lut;

    public Ptr<drm_property_blob> ctm;

    public Ptr<drm_property_blob> gamma_lut;

    public @Unsigned int target_vblank;

    public boolean async_flip;

    public boolean vrr_enabled;

    public boolean self_refresh_active;

    public drm_scaling_filter scaling_filter;

    public Ptr<drm_pending_vblank_event> event;

    public Ptr<drm_crtc_commit> commit;

    public Ptr<drm_atomic_state> state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_pending_vblank_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_pending_vblank_event extends Struct {
    public drm_pending_event base;

    public @Unsigned int pipe;

    public @Unsigned long sequence;

    public event_of_drm_pending_vblank_event event;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_crtc_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_crtc_funcs extends Struct {
    public Ptr<?> reset;

    public Ptr<?> cursor_set;

    public Ptr<?> cursor_set2;

    public Ptr<?> cursor_move;

    public Ptr<?> gamma_set;

    public Ptr<?> destroy;

    public Ptr<?> set_config;

    public Ptr<?> page_flip;

    public Ptr<?> page_flip_target;

    public Ptr<?> set_property;

    public Ptr<?> atomic_duplicate_state;

    public Ptr<?> atomic_destroy_state;

    public Ptr<?> atomic_set_property;

    public Ptr<?> atomic_get_property;

    public Ptr<?> late_register;

    public Ptr<?> early_unregister;

    public Ptr<?> set_crc_source;

    public Ptr<?> verify_crc_source;

    public Ptr<?> get_crc_sources;

    public Ptr<?> atomic_print_state;

    public Ptr<?> get_vblank_counter;

    public Ptr<?> enable_vblank;

    public Ptr<?> disable_vblank;

    public Ptr<?> get_vblank_timestamp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_set"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_set extends Struct {
    public Ptr<drm_framebuffer> fb;

    public Ptr<drm_crtc> crtc;

    public Ptr<drm_display_mode> mode;

    public @Unsigned @OriginalName("uint32_t") int x;

    public @Unsigned @OriginalName("uint32_t") int y;

    public Ptr<Ptr<drm_connector>> connectors;

    public @Unsigned long num_connectors;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_crtc_helper_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_crtc_helper_funcs extends Struct {
    public Ptr<?> dpms;

    public Ptr<?> prepare;

    public Ptr<?> commit;

    public Ptr<?> mode_valid;

    public Ptr<?> mode_fixup;

    public Ptr<?> mode_set;

    public Ptr<?> mode_set_nofb;

    public Ptr<?> mode_set_base;

    public Ptr<?> mode_set_base_atomic;

    public Ptr<?> disable;

    public Ptr<?> atomic_check;

    public Ptr<?> atomic_begin;

    public Ptr<?> atomic_flush;

    public Ptr<?> atomic_enable;

    public Ptr<?> atomic_disable;

    public Ptr<?> get_scanout_position;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct __drm_planes_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class __drm_planes_state extends Struct {
    public Ptr<drm_plane> ptr;

    public Ptr<drm_plane_state> state;

    public Ptr<drm_plane_state> old_state;

    public Ptr<drm_plane_state> new_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct __drm_crtcs_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class __drm_crtcs_state extends Struct {
    public Ptr<drm_crtc> ptr;

    public Ptr<drm_crtc_state> state;

    public Ptr<drm_crtc_state> old_state;

    public Ptr<drm_crtc_state> new_state;

    public Ptr<drm_crtc_commit> commit;

    public Ptr<java.lang.Integer> out_fence_ptr;

    public @Unsigned long last_vblank_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct __drm_connnectors_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class __drm_connnectors_state extends Struct {
    public Ptr<drm_connector> ptr;

    public Ptr<drm_connector_state> state;

    public Ptr<drm_connector_state> old_state;

    public Ptr<drm_connector_state> new_state;

    public Ptr<java.lang.Integer> out_fence_ptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_private_state_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_private_state_funcs extends Struct {
    public Ptr<?> atomic_duplicate_state;

    public Ptr<?> atomic_destroy_state;

    public Ptr<?> atomic_print_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_private_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_private_state extends Struct {
    public Ptr<drm_atomic_state> state;

    public Ptr<drm_private_obj> obj;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_private_obj"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_private_obj extends Struct {
    public list_head head;

    public drm_modeset_lock lock;

    public Ptr<drm_private_state> state;

    public Ptr<drm_private_state_funcs> funcs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct __drm_private_objs_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class __drm_private_objs_state extends Struct {
    public Ptr<drm_private_obj> ptr;

    public Ptr<drm_private_state> state;

    public Ptr<drm_private_state> old_state;

    public Ptr<drm_private_state> new_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_bus_cfg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_bus_cfg extends Struct {
    public @Unsigned int format;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_bridge_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_bridge_state extends Struct {
    public drm_private_state base;

    public Ptr<drm_bridge> bridge;

    public drm_bus_cfg input_bus_cfg;

    public drm_bus_cfg output_bus_cfg;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_bridge"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_bridge extends Struct {
    public drm_private_obj base;

    public Ptr<drm_device> dev;

    public Ptr<drm_encoder> encoder;

    public list_head chain_node;

    public Ptr<device_node> of_node;

    public list_head list;

    public Ptr<drm_bridge_timings> timings;

    public Ptr<drm_bridge_funcs> funcs;

    public Ptr<?> container;

    public kref refcount;

    public Ptr<?> driver_private;

    public drm_bridge_ops ops;

    public int type;

    public boolean interlace_allowed;

    public boolean ycbcr_420_allowed;

    public boolean pre_enable_prev_first;

    public Ptr<i2c_adapter> ddc;

    public String vendor;

    public String product;

    public @Unsigned int supported_formats;

    public @Unsigned int max_bpc;

    public Ptr<device> hdmi_cec_dev;

    public Ptr<device> hdmi_audio_dev;

    public int hdmi_audio_max_i2s_playback_channels;

    public @Unsigned long hdmi_audio_i2s_formats;

    public @Unsigned int hdmi_audio_spdif_playback;

    public int hdmi_audio_dai_port;

    public String hdmi_cec_adapter_name;

    public char hdmi_cec_available_las;

    public mutex hpd_mutex;

    public Ptr<?> hpd_cb;

    public Ptr<?> hpd_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_encoder_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_encoder_funcs extends Struct {
    public Ptr<?> reset;

    public Ptr<?> destroy;

    public Ptr<?> late_register;

    public Ptr<?> early_unregister;

    public Ptr<?> debugfs_init;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_encoder_helper_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_encoder_helper_funcs extends Struct {
    public Ptr<?> dpms;

    public Ptr<?> mode_valid;

    public Ptr<?> mode_fixup;

    public Ptr<?> prepare;

    public Ptr<?> commit;

    public Ptr<?> mode_set;

    public Ptr<?> atomic_mode_set;

    public Ptr<?> detect;

    public Ptr<?> atomic_disable;

    public Ptr<?> atomic_enable;

    public Ptr<?> disable;

    public Ptr<?> enable;

    public Ptr<?> atomic_check;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_bridge_attach_flags"
  )
  public enum drm_bridge_attach_flags implements Enum<drm_bridge_attach_flags>, TypedEnum<drm_bridge_attach_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_BRIDGE_ATTACH_NO_CONNECTOR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_BRIDGE_ATTACH_NO_CONNECTOR"
    )
    DRM_BRIDGE_ATTACH_NO_CONNECTOR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_bridge_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_bridge_funcs extends Struct {
    public Ptr<?> attach;

    public Ptr<?> destroy;

    public Ptr<?> detach;

    public Ptr<?> mode_valid;

    public Ptr<?> mode_fixup;

    public Ptr<?> disable;

    public Ptr<?> post_disable;

    public Ptr<?> mode_set;

    public Ptr<?> pre_enable;

    public Ptr<?> enable;

    public Ptr<?> atomic_pre_enable;

    public Ptr<?> atomic_enable;

    public Ptr<?> atomic_disable;

    public Ptr<?> atomic_post_disable;

    public Ptr<?> atomic_duplicate_state;

    public Ptr<?> atomic_destroy_state;

    public Ptr<?> atomic_get_output_bus_fmts;

    public Ptr<?> atomic_get_input_bus_fmts;

    public Ptr<?> atomic_check;

    public Ptr<?> atomic_reset;

    public Ptr<?> detect;

    public Ptr<?> get_modes;

    public Ptr<?> edid_read;

    public Ptr<?> hpd_notify;

    public Ptr<?> hpd_enable;

    public Ptr<?> hpd_disable;

    public Ptr<?> hdmi_tmds_char_rate_valid;

    public Ptr<?> hdmi_clear_infoframe;

    public Ptr<?> hdmi_write_infoframe;

    public Ptr<?> hdmi_audio_startup;

    public Ptr<?> hdmi_audio_prepare;

    public Ptr<?> hdmi_audio_shutdown;

    public Ptr<?> hdmi_audio_mute_stream;

    public Ptr<?> hdmi_cec_init;

    public Ptr<?> hdmi_cec_enable;

    public Ptr<?> hdmi_cec_log_addr;

    public Ptr<?> hdmi_cec_transmit;

    public Ptr<?> dp_audio_startup;

    public Ptr<?> dp_audio_prepare;

    public Ptr<?> dp_audio_shutdown;

    public Ptr<?> dp_audio_mute_stream;

    public Ptr<?> debugfs_init;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_bridge_timings"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_bridge_timings extends Struct {
    public @Unsigned int input_bus_flags;

    public @Unsigned int setup_time_ps;

    public @Unsigned int hold_time_ps;

    public boolean dual_link;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_bridge_ops"
  )
  public enum drm_bridge_ops implements Enum<drm_bridge_ops>, TypedEnum<drm_bridge_ops, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_BRIDGE_OP_DETECT = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_BRIDGE_OP_DETECT"
    )
    DRM_BRIDGE_OP_DETECT,

    /**
     * {@code DRM_BRIDGE_OP_EDID = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_BRIDGE_OP_EDID"
    )
    DRM_BRIDGE_OP_EDID,

    /**
     * {@code DRM_BRIDGE_OP_HPD = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_BRIDGE_OP_HPD"
    )
    DRM_BRIDGE_OP_HPD,

    /**
     * {@code DRM_BRIDGE_OP_MODES = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DRM_BRIDGE_OP_MODES"
    )
    DRM_BRIDGE_OP_MODES,

    /**
     * {@code DRM_BRIDGE_OP_HDMI = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DRM_BRIDGE_OP_HDMI"
    )
    DRM_BRIDGE_OP_HDMI,

    /**
     * {@code DRM_BRIDGE_OP_HDMI_AUDIO = 32}
     */
    @EnumMember(
        value = 32L,
        name = "DRM_BRIDGE_OP_HDMI_AUDIO"
    )
    DRM_BRIDGE_OP_HDMI_AUDIO,

    /**
     * {@code DRM_BRIDGE_OP_DP_AUDIO = 64}
     */
    @EnumMember(
        value = 64L,
        name = "DRM_BRIDGE_OP_DP_AUDIO"
    )
    DRM_BRIDGE_OP_DP_AUDIO,

    /**
     * {@code DRM_BRIDGE_OP_HDMI_CEC_NOTIFIER = 128}
     */
    @EnumMember(
        value = 128L,
        name = "DRM_BRIDGE_OP_HDMI_CEC_NOTIFIER"
    )
    DRM_BRIDGE_OP_HDMI_CEC_NOTIFIER,

    /**
     * {@code DRM_BRIDGE_OP_HDMI_CEC_ADAPTER = 256}
     */
    @EnumMember(
        value = 256L,
        name = "DRM_BRIDGE_OP_HDMI_CEC_ADAPTER"
    )
    DRM_BRIDGE_OP_HDMI_CEC_ADAPTER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_debugfs_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_debugfs_info extends Struct {
    public String name;

    public Ptr<?> show;

    public @Unsigned int driver_features;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_debugfs_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_debugfs_entry extends Struct {
    public Ptr<drm_device> dev;

    public drm_debugfs_info file;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_driver_feature"
  )
  public enum drm_driver_feature implements Enum<drm_driver_feature>, TypedEnum<drm_driver_feature, java.lang. @Unsigned Integer> {
    /**
     * {@code DRIVER_GEM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRIVER_GEM"
    )
    DRIVER_GEM,

    /**
     * {@code DRIVER_MODESET = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRIVER_MODESET"
    )
    DRIVER_MODESET,

    /**
     * {@code DRIVER_RENDER = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DRIVER_RENDER"
    )
    DRIVER_RENDER,

    /**
     * {@code DRIVER_ATOMIC = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DRIVER_ATOMIC"
    )
    DRIVER_ATOMIC,

    /**
     * {@code DRIVER_SYNCOBJ = 32}
     */
    @EnumMember(
        value = 32L,
        name = "DRIVER_SYNCOBJ"
    )
    DRIVER_SYNCOBJ,

    /**
     * {@code DRIVER_SYNCOBJ_TIMELINE = 64}
     */
    @EnumMember(
        value = 64L,
        name = "DRIVER_SYNCOBJ_TIMELINE"
    )
    DRIVER_SYNCOBJ_TIMELINE,

    /**
     * {@code DRIVER_COMPUTE_ACCEL = 128}
     */
    @EnumMember(
        value = 128L,
        name = "DRIVER_COMPUTE_ACCEL"
    )
    DRIVER_COMPUTE_ACCEL,

    /**
     * {@code DRIVER_GEM_GPUVA = 256}
     */
    @EnumMember(
        value = 256L,
        name = "DRIVER_GEM_GPUVA"
    )
    DRIVER_GEM_GPUVA,

    /**
     * {@code DRIVER_CURSOR_HOTSPOT = 512}
     */
    @EnumMember(
        value = 512L,
        name = "DRIVER_CURSOR_HOTSPOT"
    )
    DRIVER_CURSOR_HOTSPOT,

    /**
     * {@code DRIVER_USE_AGP = 33554432}
     */
    @EnumMember(
        value = 33554432L,
        name = "DRIVER_USE_AGP"
    )
    DRIVER_USE_AGP,

    /**
     * {@code DRIVER_LEGACY = 67108864}
     */
    @EnumMember(
        value = 67108864L,
        name = "DRIVER_LEGACY"
    )
    DRIVER_LEGACY,

    /**
     * {@code DRIVER_PCI_DMA = 134217728}
     */
    @EnumMember(
        value = 134217728L,
        name = "DRIVER_PCI_DMA"
    )
    DRIVER_PCI_DMA,

    /**
     * {@code DRIVER_SG = 268435456}
     */
    @EnumMember(
        value = 268435456L,
        name = "DRIVER_SG"
    )
    DRIVER_SG,

    /**
     * {@code DRIVER_HAVE_DMA = 536870912}
     */
    @EnumMember(
        value = 536870912L,
        name = "DRIVER_HAVE_DMA"
    )
    DRIVER_HAVE_DMA,

    /**
     * {@code DRIVER_HAVE_IRQ = 1073741824}
     */
    @EnumMember(
        value = 1073741824L,
        name = "DRIVER_HAVE_IRQ"
    )
    DRIVER_HAVE_IRQ
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_ioctl_desc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_ioctl_desc extends Struct {
    public @Unsigned int cmd;

    public drm_ioctl_flags flags;

    public Ptr<?> func;

    public String name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_prime_file_private"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_prime_file_private extends Struct {
    public mutex lock;

    public rb_root dmabufs;

    public rb_root handles;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_pending_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_pending_event extends Struct {
    public Ptr<completion> completion;

    public Ptr<?> completion_release;

    public Ptr<drm_event> event;

    public Ptr<dma_fence> fence;

    public Ptr<drm_file> file_priv;

    public list_head link;

    public list_head pending_link;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_framebuffer_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_framebuffer_funcs extends Struct {
    public Ptr<?> destroy;

    public Ptr<?> create_handle;

    public Ptr<?> dirty;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_writeback_connector"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_writeback_connector extends Struct {
    public drm_connector base;

    public drm_encoder encoder;

    public Ptr<drm_property_blob> pixel_formats_blob_ptr;

    public @OriginalName("spinlock_t") spinlock job_lock;

    public list_head job_queue;

    public @Unsigned int fence_context;

    public @OriginalName("spinlock_t") spinlock fence_lock;

    public @Unsigned long fence_seqno;

    public char @Size(32) [] timeline_name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_ioctl_flags"
  )
  public enum drm_ioctl_flags implements Enum<drm_ioctl_flags>, TypedEnum<drm_ioctl_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_AUTH = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_AUTH"
    )
    DRM_AUTH,

    /**
     * {@code DRM_MASTER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_MASTER"
    )
    DRM_MASTER,

    /**
     * {@code DRM_ROOT_ONLY = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_ROOT_ONLY"
    )
    DRM_ROOT_ONLY,

    /**
     * {@code DRM_RENDER_ALLOW = 32}
     */
    @EnumMember(
        value = 32L,
        name = "DRM_RENDER_ALLOW"
    )
    DRM_RENDER_ALLOW
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_vblank_crtc_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_vblank_crtc_config extends Struct {
    public int offdelay_ms;

    public boolean disable_immediate;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_modeinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_modeinfo extends Struct {
    public @Unsigned int clock;

    public @Unsigned short hdisplay;

    public @Unsigned short hsync_start;

    public @Unsigned short hsync_end;

    public @Unsigned short htotal;

    public @Unsigned short hskew;

    public @Unsigned short vdisplay;

    public @Unsigned short vsync_start;

    public @Unsigned short vsync_end;

    public @Unsigned short vtotal;

    public @Unsigned short vscan;

    public @Unsigned int vrefresh;

    public @Unsigned int flags;

    public @Unsigned int type;

    public char @Size(32) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_atomic"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_atomic extends Struct {
    public @Unsigned int flags;

    public @Unsigned int count_objs;

    public @Unsigned long objs_ptr;

    public @Unsigned long count_props_ptr;

    public @Unsigned long props_ptr;

    public @Unsigned long prop_values_ptr;

    public @Unsigned long reserved;

    public @Unsigned long user_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_out_fence_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_out_fence_state extends Struct {
    public Ptr<java.lang.Integer> out_fence_ptr;

    public Ptr<sync_file> sync_file;

    public int fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_master"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_master extends Struct {
    public kref refcount;

    public Ptr<drm_device> dev;

    public String unique;

    public int unique_len;

    public idr magic_map;

    public Ptr<?> driver_priv;

    public Ptr<drm_master> lessor;

    public int lessee_id;

    public list_head lessee_list;

    public list_head lessees;

    public idr leases;

    public idr lessee_idr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_auth"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_auth extends Struct {
    public @Unsigned @OriginalName("drm_magic_t") int magic;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_prop_enum_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_prop_enum_list extends Struct {
    public int type;

    public String name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_crtc_lut"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_crtc_lut extends Struct {
    public @Unsigned int crtc_id;

    public @Unsigned int gamma_size;

    public @Unsigned long red;

    public @Unsigned long green;

    public @Unsigned long blue;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_color_lut"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_color_lut extends Struct {
    public @Unsigned short red;

    public @Unsigned short green;

    public @Unsigned short blue;

    public @Unsigned short reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_color_lut_tests"
  )
  public enum drm_color_lut_tests implements Enum<drm_color_lut_tests>, TypedEnum<drm_color_lut_tests, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_COLOR_LUT_EQUAL_CHANNELS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_COLOR_LUT_EQUAL_CHANNELS"
    )
    DRM_COLOR_LUT_EQUAL_CHANNELS,

    /**
     * {@code DRM_COLOR_LUT_NON_DECREASING = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_COLOR_LUT_NON_DECREASING"
    )
    DRM_COLOR_LUT_NON_DECREASING
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_get_connector"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_get_connector extends Struct {
    public @Unsigned long encoders_ptr;

    public @Unsigned long modes_ptr;

    public @Unsigned long props_ptr;

    public @Unsigned long prop_values_ptr;

    public @Unsigned int count_modes;

    public @Unsigned int count_props;

    public @Unsigned int count_encoders;

    public @Unsigned int encoder_id;

    public @Unsigned int connector_id;

    public @Unsigned int connector_type;

    public @Unsigned int connector_type_id;

    public @Unsigned int connection;

    public @Unsigned int mm_width;

    public @Unsigned int mm_height;

    public @Unsigned int subpixel;

    public @Unsigned int pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_connector_set_property"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_connector_set_property extends Struct {
    public @Unsigned long value;

    public @Unsigned int prop_id;

    public @Unsigned int connector_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_obj_set_property"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_obj_set_property extends Struct {
    public @Unsigned long value;

    public @Unsigned int prop_id;

    public @Unsigned int obj_id;

    public @Unsigned int obj_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_panel_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_panel_funcs extends Struct {
    public Ptr<?> prepare;

    public Ptr<?> enable;

    public Ptr<?> disable;

    public Ptr<?> unprepare;

    public Ptr<?> get_modes;

    public Ptr<?> get_orientation;

    public Ptr<?> get_timings;

    public Ptr<?> debugfs_init;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_panel"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_panel extends Struct {
    public Ptr<device> dev;

    public Ptr<backlight_device> backlight;

    public Ptr<drm_panel_funcs> funcs;

    public int connector_type;

    public list_head list;

    public list_head followers;

    public mutex follower_lock;

    public boolean prepare_prev_first;

    public boolean prepared;

    public boolean enabled;

    public Ptr<?> container;

    public kref refcount;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_conn_prop_enum_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_conn_prop_enum_list extends Struct {
    public int type;

    public String name;

    public ida ida;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_crtc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_crtc extends Struct {
    public @Unsigned long set_connectors_ptr;

    public @Unsigned int count_connectors;

    public @Unsigned int crtc_id;

    public @Unsigned int fb_id;

    public @Unsigned int x;

    public @Unsigned int y;

    public @Unsigned int gamma_size;

    public @Unsigned int mode_valid;

    public drm_mode_modeinfo mode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_edid_ident"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_edid_ident extends Struct {
    public @Unsigned int panel_id;

    public String name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_minor_type"
  )
  public enum drm_minor_type implements Enum<drm_minor_type>, TypedEnum<drm_minor_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_MINOR_PRIMARY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_MINOR_PRIMARY"
    )
    DRM_MINOR_PRIMARY,

    /**
     * {@code DRM_MINOR_CONTROL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_MINOR_CONTROL"
    )
    DRM_MINOR_CONTROL,

    /**
     * {@code DRM_MINOR_RENDER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_MINOR_RENDER"
    )
    DRM_MINOR_RENDER,

    /**
     * {@code DRM_MINOR_ACCEL = 32}
     */
    @EnumMember(
        value = 32L,
        name = "DRM_MINOR_ACCEL"
    )
    DRM_MINOR_ACCEL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_wedge_task_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_wedge_task_info extends Struct {
    public @OriginalName("pid_t") int pid;

    public char @Size(16) [] comm;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_map_dumb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_map_dumb extends Struct {
    public @Unsigned int handle;

    public @Unsigned int pad;

    public @Unsigned long offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_destroy_dumb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_destroy_dumb extends Struct {
    public @Unsigned int handle;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_edid_quirk"
  )
  public enum drm_edid_quirk implements Enum<drm_edid_quirk>, TypedEnum<drm_edid_quirk, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_EDID_QUIRK_DP_DPCD_PROBE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_EDID_QUIRK_DP_DPCD_PROBE"
    )
    DRM_EDID_QUIRK_DP_DPCD_PROBE,

    /**
     * {@code DRM_EDID_QUIRK_NUM = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_EDID_QUIRK_NUM"
    )
    DRM_EDID_QUIRK_NUM
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_edid_product_id"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_edid_product_id extends Struct {
    public @Unsigned @OriginalName("__be16") short manufacturer_name;

    public @Unsigned @OriginalName("__le16") short product_code;

    public @Unsigned @OriginalName("__le32") int serial_number;

    public char week_of_manufacture;

    public char year_of_manufacture;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_edid_internal_quirk"
  )
  public enum drm_edid_internal_quirk implements Enum<drm_edid_internal_quirk>, TypedEnum<drm_edid_internal_quirk, java.lang. @Unsigned Integer> {
    /**
     * {@code EDID_QUIRK_PREFER_LARGE_60 = 1}
     */
    @EnumMember(
        value = 1L,
        name = "EDID_QUIRK_PREFER_LARGE_60"
    )
    EDID_QUIRK_PREFER_LARGE_60,

    /**
     * {@code EDID_QUIRK_135_CLOCK_TOO_HIGH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "EDID_QUIRK_135_CLOCK_TOO_HIGH"
    )
    EDID_QUIRK_135_CLOCK_TOO_HIGH,

    /**
     * {@code EDID_QUIRK_PREFER_LARGE_75 = 3}
     */
    @EnumMember(
        value = 3L,
        name = "EDID_QUIRK_PREFER_LARGE_75"
    )
    EDID_QUIRK_PREFER_LARGE_75,

    /**
     * {@code EDID_QUIRK_DETAILED_IN_CM = 4}
     */
    @EnumMember(
        value = 4L,
        name = "EDID_QUIRK_DETAILED_IN_CM"
    )
    EDID_QUIRK_DETAILED_IN_CM,

    /**
     * {@code EDID_QUIRK_DETAILED_USE_MAXIMUM_SIZE = 5}
     */
    @EnumMember(
        value = 5L,
        name = "EDID_QUIRK_DETAILED_USE_MAXIMUM_SIZE"
    )
    EDID_QUIRK_DETAILED_USE_MAXIMUM_SIZE,

    /**
     * {@code EDID_QUIRK_DETAILED_SYNC_PP = 6}
     */
    @EnumMember(
        value = 6L,
        name = "EDID_QUIRK_DETAILED_SYNC_PP"
    )
    EDID_QUIRK_DETAILED_SYNC_PP,

    /**
     * {@code EDID_QUIRK_FORCE_REDUCED_BLANKING = 7}
     */
    @EnumMember(
        value = 7L,
        name = "EDID_QUIRK_FORCE_REDUCED_BLANKING"
    )
    EDID_QUIRK_FORCE_REDUCED_BLANKING,

    /**
     * {@code EDID_QUIRK_FORCE_8BPC = 8}
     */
    @EnumMember(
        value = 8L,
        name = "EDID_QUIRK_FORCE_8BPC"
    )
    EDID_QUIRK_FORCE_8BPC,

    /**
     * {@code EDID_QUIRK_FORCE_12BPC = 9}
     */
    @EnumMember(
        value = 9L,
        name = "EDID_QUIRK_FORCE_12BPC"
    )
    EDID_QUIRK_FORCE_12BPC,

    /**
     * {@code EDID_QUIRK_FORCE_6BPC = 10}
     */
    @EnumMember(
        value = 10L,
        name = "EDID_QUIRK_FORCE_6BPC"
    )
    EDID_QUIRK_FORCE_6BPC,

    /**
     * {@code EDID_QUIRK_FORCE_10BPC = 11}
     */
    @EnumMember(
        value = 11L,
        name = "EDID_QUIRK_FORCE_10BPC"
    )
    EDID_QUIRK_FORCE_10BPC,

    /**
     * {@code EDID_QUIRK_NON_DESKTOP = 12}
     */
    @EnumMember(
        value = 12L,
        name = "EDID_QUIRK_NON_DESKTOP"
    )
    EDID_QUIRK_NON_DESKTOP,

    /**
     * {@code EDID_QUIRK_CAP_DSC_15BPP = 13}
     */
    @EnumMember(
        value = 13L,
        name = "EDID_QUIRK_CAP_DSC_15BPP"
    )
    EDID_QUIRK_CAP_DSC_15BPP
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_edid_match_closure"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_edid_match_closure extends Struct {
    public Ptr<drm_edid_ident> ident;

    public boolean matched;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_edid_iter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_edid_iter extends Struct {
    public Ptr<drm_edid> drm_edid;

    public int index;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_get_encoder"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_get_encoder extends Struct {
    public @Unsigned int encoder_id;

    public @Unsigned int encoder_type;

    public @Unsigned int crtc_id;

    public @Unsigned int possible_crtcs;

    public @Unsigned int possible_clones;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_memory_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_memory_stats extends Struct {
    public @Unsigned long shared;

    public @Unsigned long _private;

    public @Unsigned long resident;

    public @Unsigned long purgeable;

    public @Unsigned long active;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_fb_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_fb_cmd extends Struct {
    public @Unsigned int fb_id;

    public @Unsigned int width;

    public @Unsigned int height;

    public @Unsigned int pitch;

    public @Unsigned int bpp;

    public @Unsigned int depth;

    public @Unsigned int handle;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_fb_dirty_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_fb_dirty_cmd extends Struct {
    public @Unsigned int fb_id;

    public @Unsigned int flags;

    public @Unsigned int color;

    public @Unsigned int num_clips;

    public @Unsigned long clips_ptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_closefb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_closefb extends Struct {
    public @Unsigned int fb_id;

    public @Unsigned int pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_rmfb_work"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_rmfb_work extends Struct {
    public work_struct work;

    public list_head fbs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gem_close"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gem_close extends Struct {
    public @Unsigned int handle;

    public @Unsigned int pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gem_flink"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gem_flink extends Struct {
    public @Unsigned int handle;

    public @Unsigned int name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gem_open"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gem_open extends Struct {
    public @Unsigned int name;

    public @Unsigned int handle;

    public @Unsigned long size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_version"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_version extends Struct {
    public int version_major;

    public int version_minor;

    public int version_patchlevel;

    public @Unsigned @OriginalName("__kernel_size_t") long name_len;

    public String name;

    public @Unsigned @OriginalName("__kernel_size_t") long date_len;

    public String date;

    public @Unsigned @OriginalName("__kernel_size_t") long desc_len;

    public String desc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_unique"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_unique extends Struct {
    public @Unsigned @OriginalName("__kernel_size_t") long unique_len;

    public String unique;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_client"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_client extends Struct {
    public int idx;

    public int auth;

    public @Unsigned long pid;

    public @Unsigned long uid;

    public @Unsigned long magic;

    public @Unsigned long iocs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_stat_type"
  )
  public enum drm_stat_type implements Enum<drm_stat_type>, TypedEnum<drm_stat_type, java.lang. @Unsigned Integer> {
    /**
     * {@code _DRM_STAT_LOCK = 0}
     */
    @EnumMember(
        value = 0L,
        name = "_DRM_STAT_LOCK"
    )
    _DRM_STAT_LOCK,

    /**
     * {@code _DRM_STAT_OPENS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "_DRM_STAT_OPENS"
    )
    _DRM_STAT_OPENS,

    /**
     * {@code _DRM_STAT_CLOSES = 2}
     */
    @EnumMember(
        value = 2L,
        name = "_DRM_STAT_CLOSES"
    )
    _DRM_STAT_CLOSES,

    /**
     * {@code _DRM_STAT_IOCTLS = 3}
     */
    @EnumMember(
        value = 3L,
        name = "_DRM_STAT_IOCTLS"
    )
    _DRM_STAT_IOCTLS,

    /**
     * {@code _DRM_STAT_LOCKS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "_DRM_STAT_LOCKS"
    )
    _DRM_STAT_LOCKS,

    /**
     * {@code _DRM_STAT_UNLOCKS = 5}
     */
    @EnumMember(
        value = 5L,
        name = "_DRM_STAT_UNLOCKS"
    )
    _DRM_STAT_UNLOCKS,

    /**
     * {@code _DRM_STAT_VALUE = 6}
     */
    @EnumMember(
        value = 6L,
        name = "_DRM_STAT_VALUE"
    )
    _DRM_STAT_VALUE,

    /**
     * {@code _DRM_STAT_BYTE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "_DRM_STAT_BYTE"
    )
    _DRM_STAT_BYTE,

    /**
     * {@code _DRM_STAT_COUNT = 8}
     */
    @EnumMember(
        value = 8L,
        name = "_DRM_STAT_COUNT"
    )
    _DRM_STAT_COUNT,

    /**
     * {@code _DRM_STAT_IRQ = 9}
     */
    @EnumMember(
        value = 9L,
        name = "_DRM_STAT_IRQ"
    )
    _DRM_STAT_IRQ,

    /**
     * {@code _DRM_STAT_PRIMARY = 10}
     */
    @EnumMember(
        value = 10L,
        name = "_DRM_STAT_PRIMARY"
    )
    _DRM_STAT_PRIMARY,

    /**
     * {@code _DRM_STAT_SECONDARY = 11}
     */
    @EnumMember(
        value = 11L,
        name = "_DRM_STAT_SECONDARY"
    )
    _DRM_STAT_SECONDARY,

    /**
     * {@code _DRM_STAT_DMA = 12}
     */
    @EnumMember(
        value = 12L,
        name = "_DRM_STAT_DMA"
    )
    _DRM_STAT_DMA,

    /**
     * {@code _DRM_STAT_SPECIAL = 13}
     */
    @EnumMember(
        value = 13L,
        name = "_DRM_STAT_SPECIAL"
    )
    _DRM_STAT_SPECIAL,

    /**
     * {@code _DRM_STAT_MISSED = 14}
     */
    @EnumMember(
        value = 14L,
        name = "_DRM_STAT_MISSED"
    )
    _DRM_STAT_MISSED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_stats extends Struct {
    public @Unsigned long count;

    public AnonymousType2081952435C64 @Size(15) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_set_version"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_set_version extends Struct {
    public int drm_di_major;

    public int drm_di_minor;

    public int drm_dd_major;

    public int drm_dd_minor;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_get_cap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_get_cap extends Struct {
    public @Unsigned long capability;

    public @Unsigned long value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_set_client_cap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_set_client_cap extends Struct {
    public @Unsigned long capability;

    public @Unsigned long value;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_set_client_name"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_set_client_name extends Struct {
    public @Unsigned long name_len;

    public @Unsigned long name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_create_lease"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_create_lease extends Struct {
    public @Unsigned long object_ids;

    public @Unsigned int object_count;

    public @Unsigned int flags;

    public @Unsigned int lessee_id;

    public @Unsigned int fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_list_lessees"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_list_lessees extends Struct {
    public @Unsigned int count_lessees;

    public @Unsigned int pad;

    public @Unsigned long lessees_ptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_get_lease"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_get_lease extends Struct {
    public @Unsigned int count_objects;

    public @Unsigned int pad;

    public @Unsigned long objects_ptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_revoke_lease"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_revoke_lease extends Struct {
    public @Unsigned int lessee_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_mm_insert_mode"
  )
  public enum drm_mm_insert_mode implements Enum<drm_mm_insert_mode>, TypedEnum<drm_mm_insert_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_MM_INSERT_BEST = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_MM_INSERT_BEST"
    )
    DRM_MM_INSERT_BEST,

    /**
     * {@code DRM_MM_INSERT_LOW = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_MM_INSERT_LOW"
    )
    DRM_MM_INSERT_LOW,

    /**
     * {@code DRM_MM_INSERT_HIGH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_MM_INSERT_HIGH"
    )
    DRM_MM_INSERT_HIGH,

    /**
     * {@code DRM_MM_INSERT_EVICT = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DRM_MM_INSERT_EVICT"
    )
    DRM_MM_INSERT_EVICT,

    /**
     * {@code DRM_MM_INSERT_ONCE = -2147483648}
     */
    @EnumMember(
        value = -2147483648L,
        name = "DRM_MM_INSERT_ONCE"
    )
    DRM_MM_INSERT_ONCE,

    /**
     * {@code DRM_MM_INSERT_HIGHEST = -2147483646}
     */
    @EnumMember(
        value = -2147483646L,
        name = "DRM_MM_INSERT_HIGHEST"
    )
    DRM_MM_INSERT_HIGHEST,

    /**
     * {@code DRM_MM_INSERT_LOWEST = -2147483647}
     */
    @EnumMember(
        value = -2147483647L,
        name = "DRM_MM_INSERT_LOWEST"
    )
    DRM_MM_INSERT_LOWEST
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mm_scan"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mm_scan extends Struct {
    public Ptr<drm_mm> mm;

    public @Unsigned long size;

    public @Unsigned long alignment;

    public @Unsigned long remainder_mask;

    public @Unsigned long range_start;

    public @Unsigned long range_end;

    public @Unsigned long hit_start;

    public @Unsigned long hit_end;

    public @Unsigned long color;

    public drm_mm_insert_mode mode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_card_res"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_card_res extends Struct {
    public @Unsigned long fb_id_ptr;

    public @Unsigned long crtc_id_ptr;

    public @Unsigned long connector_id_ptr;

    public @Unsigned long encoder_id_ptr;

    public @Unsigned int count_fbs;

    public @Unsigned int count_crtcs;

    public @Unsigned int count_connectors;

    public @Unsigned int count_encoders;

    public @Unsigned int min_width;

    public @Unsigned int max_width;

    public @Unsigned int min_height;

    public @Unsigned int max_height;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_obj_get_properties"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_obj_get_properties extends Struct {
    public @Unsigned long props_ptr;

    public @Unsigned long prop_values_ptr;

    public @Unsigned int count_props;

    public @Unsigned int obj_id;

    public @Unsigned int obj_type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_bus_flags"
  )
  public enum drm_bus_flags implements Enum<drm_bus_flags>, TypedEnum<drm_bus_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_BUS_FLAG_DE_LOW = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_BUS_FLAG_DE_LOW"
    )
    DRM_BUS_FLAG_DE_LOW,

    /**
     * {@code DRM_BUS_FLAG_DE_HIGH = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_BUS_FLAG_DE_HIGH"
    )
    DRM_BUS_FLAG_DE_HIGH,

    /**
     * {@code DRM_BUS_FLAG_PIXDATA_DRIVE_POSEDGE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_BUS_FLAG_PIXDATA_DRIVE_POSEDGE"
    )
    DRM_BUS_FLAG_PIXDATA_DRIVE_POSEDGE,

    /**
     * {@code DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE"
    )
    DRM_BUS_FLAG_PIXDATA_DRIVE_NEGEDGE,

    /**
     * {@code DRM_BUS_FLAG_PIXDATA_SAMPLE_POSEDGE = 8}
     */
    @EnumMember(
        value = 8L,
        name = "DRM_BUS_FLAG_PIXDATA_SAMPLE_POSEDGE"
    )
    DRM_BUS_FLAG_PIXDATA_SAMPLE_POSEDGE,

    /**
     * {@code DRM_BUS_FLAG_PIXDATA_SAMPLE_NEGEDGE = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_BUS_FLAG_PIXDATA_SAMPLE_NEGEDGE"
    )
    DRM_BUS_FLAG_PIXDATA_SAMPLE_NEGEDGE,

    /**
     * {@code DRM_BUS_FLAG_DATA_MSB_TO_LSB = 16}
     */
    @EnumMember(
        value = 16L,
        name = "DRM_BUS_FLAG_DATA_MSB_TO_LSB"
    )
    DRM_BUS_FLAG_DATA_MSB_TO_LSB,

    /**
     * {@code DRM_BUS_FLAG_DATA_LSB_TO_MSB = 32}
     */
    @EnumMember(
        value = 32L,
        name = "DRM_BUS_FLAG_DATA_LSB_TO_MSB"
    )
    DRM_BUS_FLAG_DATA_LSB_TO_MSB,

    /**
     * {@code DRM_BUS_FLAG_SYNC_DRIVE_POSEDGE = 64}
     */
    @EnumMember(
        value = 64L,
        name = "DRM_BUS_FLAG_SYNC_DRIVE_POSEDGE"
    )
    DRM_BUS_FLAG_SYNC_DRIVE_POSEDGE,

    /**
     * {@code DRM_BUS_FLAG_SYNC_DRIVE_NEGEDGE = 128}
     */
    @EnumMember(
        value = 128L,
        name = "DRM_BUS_FLAG_SYNC_DRIVE_NEGEDGE"
    )
    DRM_BUS_FLAG_SYNC_DRIVE_NEGEDGE,

    /**
     * {@code DRM_BUS_FLAG_SYNC_SAMPLE_POSEDGE = 128}
     */
    @EnumMember(
        value = 128L,
        name = "DRM_BUS_FLAG_SYNC_SAMPLE_POSEDGE"
    )
    DRM_BUS_FLAG_SYNC_SAMPLE_POSEDGE,

    /**
     * {@code DRM_BUS_FLAG_SYNC_SAMPLE_NEGEDGE = 64}
     */
    @EnumMember(
        value = 64L,
        name = "DRM_BUS_FLAG_SYNC_SAMPLE_NEGEDGE"
    )
    DRM_BUS_FLAG_SYNC_SAMPLE_NEGEDGE,

    /**
     * {@code DRM_BUS_FLAG_SHARP_SIGNALS = 256}
     */
    @EnumMember(
        value = 256L,
        name = "DRM_BUS_FLAG_SHARP_SIGNALS"
    )
    DRM_BUS_FLAG_SHARP_SIGNALS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_mode_analog"
  )
  public enum drm_mode_analog implements Enum<drm_mode_analog>, TypedEnum<drm_mode_analog, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_MODE_ANALOG_NTSC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_MODE_ANALOG_NTSC"
    )
    DRM_MODE_ANALOG_NTSC,

    /**
     * {@code DRM_MODE_ANALOG_PAL = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_MODE_ANALOG_PAL"
    )
    DRM_MODE_ANALOG_PAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_named_mode"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_named_mode extends Struct {
    public String name;

    public @Unsigned int pixel_clock_khz;

    public @Unsigned int xres;

    public @Unsigned int yres;

    public @Unsigned int flags;

    public @Unsigned int tv_mode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_set_plane"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_set_plane extends Struct {
    public @Unsigned int plane_id;

    public @Unsigned int crtc_id;

    public @Unsigned int fb_id;

    public @Unsigned int flags;

    public int crtc_x;

    public int crtc_y;

    public @Unsigned int crtc_w;

    public @Unsigned int crtc_h;

    public @Unsigned int src_x;

    public @Unsigned int src_y;

    public @Unsigned int src_h;

    public @Unsigned int src_w;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_get_plane"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_get_plane extends Struct {
    public @Unsigned int plane_id;

    public @Unsigned int crtc_id;

    public @Unsigned int fb_id;

    public @Unsigned int possible_crtcs;

    public @Unsigned int gamma_size;

    public @Unsigned int count_format_types;

    public @Unsigned long format_type_ptr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_get_plane_res"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_get_plane_res extends Struct {
    public @Unsigned long plane_id_ptr;

    public @Unsigned int count_planes;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_cursor"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_cursor extends Struct {
    public @Unsigned int flags;

    public @Unsigned int crtc_id;

    public int x;

    public int y;

    public @Unsigned int width;

    public @Unsigned int height;

    public @Unsigned int handle;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_cursor2"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_cursor2 extends Struct {
    public @Unsigned int flags;

    public @Unsigned int crtc_id;

    public int x;

    public int y;

    public @Unsigned int width;

    public @Unsigned int height;

    public @Unsigned int handle;

    public int hot_x;

    public int hot_y;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_plane_size_hint"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_plane_size_hint extends Struct {
    public @Unsigned short width;

    public @Unsigned short height;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_crtc_page_flip_target"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_crtc_page_flip_target extends Struct {
    public @Unsigned int crtc_id;

    public @Unsigned int fb_id;

    public @Unsigned int flags;

    public @Unsigned int sequence;

    public @Unsigned long user_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_format_modifier_blob"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_format_modifier_blob extends Struct {
    public @Unsigned int version;

    public @Unsigned int flags;

    public @Unsigned int count_formats;

    public @Unsigned int formats_offset;

    public @Unsigned int count_modifiers;

    public @Unsigned int modifiers_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_format_modifier"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_format_modifier extends Struct {
    public @Unsigned long formats;

    public @Unsigned int offset;

    public @Unsigned int pad;

    public @Unsigned long modifier;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_prime_handle"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_prime_handle extends Struct {
    public @Unsigned int handle;

    public @Unsigned int flags;

    public int fd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_prime_member"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_prime_member extends Struct {
    public Ptr<dma_buf> dma_buf;

    public @Unsigned @OriginalName("uint32_t") int handle;

    public rb_node dmabuf_rb;

    public rb_node handle_rb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_print_iterator"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_print_iterator extends Struct {
    public Ptr<?> data;

    public @OriginalName("ssize_t") long start;

    public @OriginalName("ssize_t") long remain;

    public @OriginalName("ssize_t") long offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_property_enum"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_property_enum extends Struct {
    public @Unsigned long value;

    public char @Size(32) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_get_property"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_get_property extends Struct {
    public @Unsigned long values_ptr;

    public @Unsigned long enum_blob_ptr;

    public @Unsigned int prop_id;

    public @Unsigned int flags;

    public char @Size(32) [] name;

    public @Unsigned int count_values;

    public @Unsigned int count_enum_blobs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_get_blob"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_get_blob extends Struct {
    public @Unsigned int blob_id;

    public @Unsigned int length;

    public @Unsigned long data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_create_blob"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_create_blob extends Struct {
    public @Unsigned long data;

    public @Unsigned int length;

    public @Unsigned int blob_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_destroy_blob"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_destroy_blob extends Struct {
    public @Unsigned int blob_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_property_enum"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_property_enum extends Struct {
    public @Unsigned @OriginalName("uint64_t") long value;

    public list_head head;

    public char @Size(32) [] name;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_syncobj_create"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_syncobj_create extends Struct {
    public @Unsigned int handle;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_syncobj_destroy"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_syncobj_destroy extends Struct {
    public @Unsigned int handle;

    public @Unsigned int pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_syncobj_handle"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_syncobj_handle extends Struct {
    public @Unsigned int handle;

    public @Unsigned int flags;

    public int fd;

    public @Unsigned int pad;

    public @Unsigned long point;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_syncobj_transfer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_syncobj_transfer extends Struct {
    public @Unsigned int src_handle;

    public @Unsigned int dst_handle;

    public @Unsigned long src_point;

    public @Unsigned long dst_point;

    public @Unsigned int flags;

    public @Unsigned int pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_syncobj_wait"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_syncobj_wait extends Struct {
    public @Unsigned long handles;

    public long timeout_nsec;

    public @Unsigned int count_handles;

    public @Unsigned int flags;

    public @Unsigned int first_signaled;

    public @Unsigned int pad;

    public @Unsigned long deadline_nsec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_syncobj_timeline_wait"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_syncobj_timeline_wait extends Struct {
    public @Unsigned long handles;

    public @Unsigned long points;

    public long timeout_nsec;

    public @Unsigned int count_handles;

    public @Unsigned int flags;

    public @Unsigned int first_signaled;

    public @Unsigned int pad;

    public @Unsigned long deadline_nsec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_syncobj_eventfd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_syncobj_eventfd extends Struct {
    public @Unsigned int handle;

    public @Unsigned int flags;

    public @Unsigned long point;

    public int fd;

    public @Unsigned int pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_syncobj_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_syncobj_array extends Struct {
    public @Unsigned long handles;

    public @Unsigned int count_handles;

    public @Unsigned int pad;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_syncobj_timeline_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_syncobj_timeline_array extends Struct {
    public @Unsigned long handles;

    public @Unsigned long points;

    public @Unsigned int count_handles;

    public @Unsigned int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_syncobj"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_syncobj extends Struct {
    public kref refcount;

    public Ptr<dma_fence> fence;

    public list_head cb_list;

    public list_head ev_fd_list;

    public @OriginalName("spinlock_t") spinlock lock;

    public Ptr<file> file;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_vblank_seq_type"
  )
  public enum drm_vblank_seq_type implements Enum<drm_vblank_seq_type>, TypedEnum<drm_vblank_seq_type, java.lang. @Unsigned Integer> {
    /**
     * {@code _DRM_VBLANK_ABSOLUTE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "_DRM_VBLANK_ABSOLUTE"
    )
    _DRM_VBLANK_ABSOLUTE,

    /**
     * {@code _DRM_VBLANK_RELATIVE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "_DRM_VBLANK_RELATIVE"
    )
    _DRM_VBLANK_RELATIVE,

    /**
     * {@code _DRM_VBLANK_HIGH_CRTC_MASK = 62}
     */
    @EnumMember(
        value = 62L,
        name = "_DRM_VBLANK_HIGH_CRTC_MASK"
    )
    _DRM_VBLANK_HIGH_CRTC_MASK,

    /**
     * {@code _DRM_VBLANK_EVENT = 67108864}
     */
    @EnumMember(
        value = 67108864L,
        name = "_DRM_VBLANK_EVENT"
    )
    _DRM_VBLANK_EVENT,

    /**
     * {@code _DRM_VBLANK_FLIP = 134217728}
     */
    @EnumMember(
        value = 134217728L,
        name = "_DRM_VBLANK_FLIP"
    )
    _DRM_VBLANK_FLIP,

    /**
     * {@code _DRM_VBLANK_NEXTONMISS = 268435456}
     */
    @EnumMember(
        value = 268435456L,
        name = "_DRM_VBLANK_NEXTONMISS"
    )
    _DRM_VBLANK_NEXTONMISS,

    /**
     * {@code _DRM_VBLANK_SECONDARY = 536870912}
     */
    @EnumMember(
        value = 536870912L,
        name = "_DRM_VBLANK_SECONDARY"
    )
    _DRM_VBLANK_SECONDARY,

    /**
     * {@code _DRM_VBLANK_SIGNAL = 1073741824}
     */
    @EnumMember(
        value = 1073741824L,
        name = "_DRM_VBLANK_SIGNAL"
    )
    _DRM_VBLANK_SIGNAL
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_wait_vblank_request"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_wait_vblank_request extends Struct {
    public drm_vblank_seq_type type;

    public @Unsigned int sequence;

    public @Unsigned long signal;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_wait_vblank_reply"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_wait_vblank_reply extends Struct {
    public drm_vblank_seq_type type;

    public @Unsigned int sequence;

    public long tval_sec;

    public long tval_usec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union drm_wait_vblank"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_wait_vblank extends Union {
    public drm_wait_vblank_request request;

    public drm_wait_vblank_reply reply;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_crtc_get_sequence"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_crtc_get_sequence extends Struct {
    public @Unsigned int crtc_id;

    public @Unsigned int active;

    public @Unsigned long sequence;

    public long sequence_ns;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_crtc_queue_sequence"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_crtc_queue_sequence extends Struct {
    public @Unsigned int crtc_id;

    public @Unsigned int flags;

    public @Unsigned long sequence;

    public @Unsigned long user_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_vblank_work"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_vblank_work extends Struct {
    public kthread_work base;

    public Ptr<drm_vblank_crtc> vblank;

    public @Unsigned long count;

    public int cancelling;

    public list_head node;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_vma_offset_file"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_vma_offset_file extends Struct {
    public rb_node vm_rb;

    public Ptr<drm_file> vm_tag;

    public @Unsigned long vm_count;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_client_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_client_funcs extends Struct {
    public Ptr<module> owner;

    public Ptr<?> unregister;

    public Ptr<?> restore;

    public Ptr<?> hotplug;

    public Ptr<?> suspend;

    public Ptr<?> resume;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_client_dev"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_client_dev extends Struct {
    public Ptr<drm_device> dev;

    public String name;

    public list_head list;

    public Ptr<drm_client_funcs> funcs;

    public Ptr<drm_file> file;

    public mutex modeset_mutex;

    public Ptr<drm_mode_set> modesets;

    public boolean suspended;

    public boolean hotplug_pending;

    public boolean hotplug_failed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_client_buffer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_client_buffer extends Struct {
    public Ptr<drm_client_dev> client;

    public @Unsigned int pitch;

    public Ptr<drm_gem_object> gem;

    public iosys_map map;

    public Ptr<drm_framebuffer> fb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_client_offset"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_client_offset extends Struct {
    public int x;

    public int y;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_version_32"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_version_32 extends Struct {
    public int version_major;

    public int version_minor;

    public int version_patchlevel;

    public @Unsigned int name_len;

    public @Unsigned int name;

    public @Unsigned int date_len;

    public @Unsigned int date;

    public @Unsigned int desc_len;

    public @Unsigned int desc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_unique32"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_unique32 extends Struct {
    public @Unsigned int unique_len;

    public @Unsigned int unique;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_client32"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_client32 extends Struct {
    public int idx;

    public int auth;

    public @Unsigned int pid;

    public @Unsigned int uid;

    public @Unsigned int magic;

    public @Unsigned int iocs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_stats32"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_stats32 extends Struct {
    public @Unsigned int count;

    public AnonymousType1269826537C59 @Size(15) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_wait_vblank_request32"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_wait_vblank_request32 extends Struct {
    public drm_vblank_seq_type type;

    public @Unsigned int sequence;

    public @Unsigned int signal;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_wait_vblank_reply32"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_wait_vblank_reply32 extends Struct {
    public drm_vblank_seq_type type;

    public @Unsigned int sequence;

    public int tval_sec;

    public int tval_usec;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union drm_wait_vblank32"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_wait_vblank32 extends Union {
    public drm_wait_vblank_request32 request;

    public drm_wait_vblank_reply32 reply;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_mode_fb_cmd232"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_mode_fb_cmd232 extends Struct {
    public @Unsigned int fb_id;

    public @Unsigned int width;

    public @Unsigned int height;

    public @Unsigned int pixel_format;

    public @Unsigned int flags;

    public @Unsigned int @Size(4) [] handles;

    public @Unsigned int @Size(4) [] pitches;

    public @Unsigned int @Size(4) [] offsets;

    public @Unsigned long @Size(4) [] modifier;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_panel_follower_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_panel_follower_funcs extends Struct {
    public Ptr<?> panel_prepared;

    public Ptr<?> panel_unpreparing;

    public Ptr<?> panel_enabled;

    public Ptr<?> panel_disabling;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_panel_follower"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_panel_follower extends Struct {
    public Ptr<drm_panel_follower_funcs> funcs;

    public list_head list;

    public Ptr<drm_panel> panel;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_exec"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_exec extends Struct {
    public @Unsigned int flags;

    public ww_acquire_ctx ticket;

    public @Unsigned int num_objects;

    public @Unsigned int max_objects;

    public Ptr<Ptr<drm_gem_object>> objects;

    public Ptr<drm_gem_object> contended;

    public Ptr<drm_gem_object> prelocked;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_gpuva_flags"
  )
  public enum drm_gpuva_flags implements Enum<drm_gpuva_flags>, TypedEnum<drm_gpuva_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_GPUVA_INVALIDATED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_GPUVA_INVALIDATED"
    )
    DRM_GPUVA_INVALIDATED,

    /**
     * {@code DRM_GPUVA_SPARSE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_GPUVA_SPARSE"
    )
    DRM_GPUVA_SPARSE,

    /**
     * {@code DRM_GPUVA_USERBITS = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_GPUVA_USERBITS"
    )
    DRM_GPUVA_USERBITS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gpuva"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gpuva extends Struct {
    public Ptr<drm_gpuvm> vm;

    public Ptr<drm_gpuvm_bo> vm_bo;

    public drm_gpuva_flags flags;

    public va_of_drm_gpuva_and_va_of_drm_gpuva_op_map va;

    public gem_of_drm_gpuva gem;

    public rb_of_drm_gpuva rb;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gpuvm"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gpuvm extends Struct {
    public String name;

    public drm_gpuvm_flags flags;

    public Ptr<drm_device> drm;

    public @Unsigned long mm_start;

    public @Unsigned long mm_range;

    public rb_of_drm_gpuvm rb;

    public kref kref;

    public drm_gpuva kernel_alloc_node;

    public Ptr<drm_gpuvm_ops> ops;

    public Ptr<drm_gem_object> r_obj;

    public evict_of_drm_gpuvm_and_extobj_of_drm_gpuvm extobj;

    public evict_of_drm_gpuvm_and_extobj_of_drm_gpuvm evict;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gpuvm_bo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gpuvm_bo extends Struct {
    public Ptr<drm_gpuvm> vm;

    public Ptr<drm_gem_object> obj;

    public boolean evicted;

    public kref kref;

    public list_of_drm_gpuvm_bo list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_gpuvm_flags"
  )
  public enum drm_gpuvm_flags implements Enum<drm_gpuvm_flags>, TypedEnum<drm_gpuvm_flags, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_GPUVM_RESV_PROTECTED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_GPUVM_RESV_PROTECTED"
    )
    DRM_GPUVM_RESV_PROTECTED,

    /**
     * {@code DRM_GPUVM_USERBITS = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_GPUVM_USERBITS"
    )
    DRM_GPUVM_USERBITS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gpuvm_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gpuvm_ops extends Struct {
    public Ptr<?> vm_free;

    public Ptr<?> op_alloc;

    public Ptr<?> op_free;

    public Ptr<?> vm_bo_alloc;

    public Ptr<?> vm_bo_free;

    public Ptr<?> vm_bo_validate;

    public Ptr<?> sm_step_map;

    public Ptr<?> sm_step_remap;

    public Ptr<?> sm_step_unmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum drm_gpuva_op_type"
  )
  public enum drm_gpuva_op_type implements Enum<drm_gpuva_op_type>, TypedEnum<drm_gpuva_op_type, java.lang. @Unsigned Integer> {
    /**
     * {@code DRM_GPUVA_OP_MAP = 0}
     */
    @EnumMember(
        value = 0L,
        name = "DRM_GPUVA_OP_MAP"
    )
    DRM_GPUVA_OP_MAP,

    /**
     * {@code DRM_GPUVA_OP_REMAP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "DRM_GPUVA_OP_REMAP"
    )
    DRM_GPUVA_OP_REMAP,

    /**
     * {@code DRM_GPUVA_OP_UNMAP = 2}
     */
    @EnumMember(
        value = 2L,
        name = "DRM_GPUVA_OP_UNMAP"
    )
    DRM_GPUVA_OP_UNMAP,

    /**
     * {@code DRM_GPUVA_OP_PREFETCH = 3}
     */
    @EnumMember(
        value = 3L,
        name = "DRM_GPUVA_OP_PREFETCH"
    )
    DRM_GPUVA_OP_PREFETCH,

    /**
     * {@code DRM_GPUVA_OP_DRIVER = 4}
     */
    @EnumMember(
        value = 4L,
        name = "DRM_GPUVA_OP_DRIVER"
    )
    DRM_GPUVA_OP_DRIVER
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gpuva_op_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gpuva_op_map extends Struct {
    public va_of_drm_gpuva_and_va_of_drm_gpuva_op_map va;

    public gem_of_drm_gpuva_op_map gem;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gpuva_op_unmap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gpuva_op_unmap extends Struct {
    public Ptr<drm_gpuva> va;

    public boolean keep;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gpuva_op_remap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gpuva_op_remap extends Struct {
    public Ptr<drm_gpuva_op_map> prev;

    public Ptr<drm_gpuva_op_map> next;

    public Ptr<drm_gpuva_op_unmap> unmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gpuva_op_prefetch"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gpuva_op_prefetch extends Struct {
    public Ptr<drm_gpuva> va;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gpuva_op"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gpuva_op extends Struct {
    public list_head entry;

    public drm_gpuva_op_type op;

    @InlineUnion(49229)
    public drm_gpuva_op_map map;

    @InlineUnion(49229)
    public drm_gpuva_op_remap remap;

    @InlineUnion(49229)
    public drm_gpuva_op_unmap unmap;

    @InlineUnion(49229)
    public drm_gpuva_op_prefetch prefetch;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_info_list"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_info_list extends Struct {
    public String name;

    public Ptr<?> show;

    public @Unsigned int driver_features;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_info_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_info_node extends Struct {
    public Ptr<drm_minor> minor;

    public Ptr<drm_info_list> info_ent;

    public list_head list;

    public Ptr<dentry> dent;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_privacy_screen_lookup"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_privacy_screen_lookup extends Struct {
    public list_head list;

    public String dev_id;

    public String con_id;

    public String provider;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_privacy_screen"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_privacy_screen extends Struct {
    public device dev;

    public mutex lock;

    public list_head list;

    public blocking_notifier_head notifier_head;

    public Ptr<drm_privacy_screen_ops> ops;

    public drm_privacy_screen_status sw_state;

    public drm_privacy_screen_status hw_state;

    public Ptr<?> drvdata;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_privacy_screen_ops"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_privacy_screen_ops extends Struct {
    public Ptr<?> set_sw_state;

    public Ptr<?> get_hw_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_scanout_buffer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_scanout_buffer extends Struct {
    public Ptr<drm_format_info> format;

    public iosys_map @Size(4) [] map;

    public Ptr<Ptr<page>> pages;

    public @Unsigned int width;

    public @Unsigned int height;

    public @Unsigned int @Size(4) [] pitch;

    public Ptr<?> set_pixel;

    public Ptr<?> _private;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_panic_line"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_panic_line extends Struct {
    public @Unsigned int len;

    public String txt;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_dmi_panel_orientation_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_dmi_panel_orientation_data extends Struct {
    public int width;

    public int height;

    public Ptr<String> bios_dates;

    public int orientation;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_gem_shmem_object"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_gem_shmem_object extends Struct {
    public drm_gem_object base;

    public Ptr<Ptr<page>> pages;

    public @OriginalName("refcount_t") refcount_struct pages_use_count;

    public @OriginalName("refcount_t") refcount_struct pages_pin_count;

    public int madv;

    public list_head madv_list;

    public Ptr<sg_table> sgt;

    public Ptr<?> vaddr;

    public @OriginalName("refcount_t") refcount_struct vmap_use_count;

    public boolean pages_mark_dirty_on_put;

    public boolean pages_mark_accessed_on_put;

    public boolean map_wc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_fb_helper"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_fb_helper extends Struct {
    public drm_client_dev client;

    public Ptr<drm_client_buffer> buffer;

    public Ptr<drm_framebuffer> fb;

    public Ptr<drm_device> dev;

    public Ptr<drm_fb_helper_funcs> funcs;

    public Ptr<fb_info> info;

    public @Unsigned int @Size(17) [] pseudo_palette;

    public drm_clip_rect damage_clip;

    public @OriginalName("spinlock_t") spinlock damage_lock;

    public work_struct damage_work;

    public work_struct resume_work;

    public mutex lock;

    public list_head kernel_fb_list;

    public boolean delayed_hotplug;

    public boolean deferred_setup;

    public int preferred_bpp;

    public fb_deferred_io fbdefio;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_fb_helper_surface_size"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_fb_helper_surface_size extends Struct {
    public @Unsigned int fb_width;

    public @Unsigned int fb_height;

    public @Unsigned int surface_width;

    public @Unsigned int surface_height;

    public @Unsigned int surface_bpp;

    public @Unsigned int surface_depth;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_fb_helper_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_fb_helper_funcs extends Struct {
    public Ptr<?> fb_dirty;

    public Ptr<?> fb_restore;

    public Ptr<?> fb_set_suspend;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_atomic_helper_damage_iter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_atomic_helper_damage_iter extends Struct {
    public drm_rect plane_src;

    public Ptr<drm_rect> clips;

    public @Unsigned @OriginalName("uint32_t") int num_clips;

    public @Unsigned @OriginalName("uint32_t") int curr_clip;

    public boolean full_update;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_flip_work"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_flip_work extends Struct {
    public String name;

    public @OriginalName("drm_flip_func_t") Ptr<?> func;

    public work_struct worker;

    public list_head queued;

    public list_head commited;

    public @OriginalName("spinlock_t") spinlock lock;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_flip_task"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_flip_task extends Struct {
    public list_head node;

    public Ptr<?> data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_format_conv_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_format_conv_state extends Struct {
    public tmp_of_drm_format_conv_state tmp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_shadow_plane_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_shadow_plane_state extends Struct {
    public drm_plane_state base;

    public drm_format_conv_state fmtcnv_state;

    public iosys_map @Size(4) [] map;

    public iosys_map @Size(4) [] data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_simple_display_pipe_funcs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_simple_display_pipe_funcs extends Struct {
    public Ptr<?> mode_valid;

    public Ptr<?> enable;

    public Ptr<?> disable;

    public Ptr<?> check;

    public Ptr<?> update;

    public Ptr<?> prepare_fb;

    public Ptr<?> cleanup_fb;

    public Ptr<?> begin_fb_access;

    public Ptr<?> end_fb_access;

    public Ptr<?> enable_vblank;

    public Ptr<?> disable_vblank;

    public Ptr<?> reset_crtc;

    public Ptr<?> duplicate_crtc_state;

    public Ptr<?> destroy_crtc_state;

    public Ptr<?> reset_plane;

    public Ptr<?> duplicate_plane_state;

    public Ptr<?> destroy_plane_state;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_simple_display_pipe"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_simple_display_pipe extends Struct {
    public drm_crtc crtc;

    public drm_plane plane;

    public drm_encoder encoder;

    public Ptr<drm_connector> connector;

    public Ptr<drm_simple_display_pipe_funcs> funcs;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_afbc_framebuffer"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_afbc_framebuffer extends Struct {
    public drm_framebuffer base;

    public @Unsigned int block_width;

    public @Unsigned int block_height;

    public @Unsigned int aligned_width;

    public @Unsigned int aligned_height;

    public @Unsigned int offset;

    public @Unsigned int afbc_size;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_self_refresh_data"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_self_refresh_data extends Struct {
    public Ptr<drm_crtc> crtc;

    public delayed_work entry_work;

    public mutex avg_mutex;

    public ewma_psr_time entry_avg_ms;

    public ewma_psr_time exit_avg_ms;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_dsc_rc_range_parameters"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_dsc_rc_range_parameters extends Struct {
    public char range_min_qp;

    public char range_max_qp;

    public char range_bpg_offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_dsc_config"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_dsc_config extends Struct {
    public char line_buf_depth;

    public char bits_per_component;

    public boolean convert_rgb;

    public char slice_count;

    public @Unsigned short slice_width;

    public @Unsigned short slice_height;

    public boolean simple_422;

    public @Unsigned short pic_width;

    public @Unsigned short pic_height;

    public char rc_tgt_offset_high;

    public char rc_tgt_offset_low;

    public @Unsigned short bits_per_pixel;

    public char rc_edge_factor;

    public char rc_quant_incr_limit1;

    public char rc_quant_incr_limit0;

    public @Unsigned short initial_xmit_delay;

    public @Unsigned short initial_dec_delay;

    public boolean block_pred_enable;

    public char first_line_bpg_offset;

    public @Unsigned short initial_offset;

    public @Unsigned short @Size(14) [] rc_buf_thresh;

    public drm_dsc_rc_range_parameters @Size(15) [] rc_range_params;

    public @Unsigned short rc_model_size;

    public char flatness_min_qp;

    public char flatness_max_qp;

    public char initial_scale_value;

    public @Unsigned short scale_decrement_interval;

    public @Unsigned short scale_increment_interval;

    public @Unsigned short nfl_bpg_offset;

    public @Unsigned short slice_bpg_offset;

    public @Unsigned short final_offset;

    public boolean vbr_enable;

    public char mux_word_size;

    public @Unsigned short slice_chunk_size;

    public @Unsigned short rc_bits;

    public char dsc_version_minor;

    public char dsc_version_major;

    public boolean native_422;

    public boolean native_420;

    public char second_line_bpg_offset;

    public @Unsigned short nsl_bpg_offset;

    public @Unsigned short second_line_offset_adj;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_dsc_picture_parameter_set"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_dsc_picture_parameter_set extends Struct {
    public char dsc_version;

    public char pps_identifier;

    public char pps_reserved;

    public char pps_3;

    public char pps_4;

    public char bits_per_pixel_low;

    public @Unsigned @OriginalName("__be16") short pic_height;

    public @Unsigned @OriginalName("__be16") short pic_width;

    public @Unsigned @OriginalName("__be16") short slice_height;

    public @Unsigned @OriginalName("__be16") short slice_width;

    public @Unsigned @OriginalName("__be16") short chunk_size;

    public char initial_xmit_delay_high;

    public char initial_xmit_delay_low;

    public @Unsigned @OriginalName("__be16") short initial_dec_delay;

    public char pps20_reserved;

    public char initial_scale_value;

    public @Unsigned @OriginalName("__be16") short scale_increment_interval;

    public char scale_decrement_interval_high;

    public char scale_decrement_interval_low;

    public char pps26_reserved;

    public char first_line_bpg_offset;

    public @Unsigned @OriginalName("__be16") short nfl_bpg_offset;

    public @Unsigned @OriginalName("__be16") short slice_bpg_offset;

    public @Unsigned @OriginalName("__be16") short initial_offset;

    public @Unsigned @OriginalName("__be16") short final_offset;

    public char flatness_min_qp;

    public char flatness_max_qp;

    public @Unsigned @OriginalName("__be16") short rc_model_size;

    public char rc_edge_factor;

    public char rc_quant_incr_limit0;

    public char rc_quant_incr_limit1;

    public char rc_tgt_offset;

    public char @Size(14) [] rc_buf_thresh;

    public @Unsigned @OriginalName("__be16") short @Size(15) [] rc_range_parameters;

    public char native_422_420;

    public char second_line_bpg_offset;

    public @Unsigned @OriginalName("__be16") short nsl_bpg_offset;

    public @Unsigned @OriginalName("__be16") short second_line_offset_adj;

    public @Unsigned int pps_long_94_reserved;

    public @Unsigned int pps_long_98_reserved;

    public @Unsigned int pps_long_102_reserved;

    public @Unsigned int pps_long_106_reserved;

    public @Unsigned int pps_long_110_reserved;

    public @Unsigned int pps_long_114_reserved;

    public @Unsigned int pps_long_118_reserved;

    public @Unsigned int pps_long_122_reserved;

    public @Unsigned @OriginalName("__be16") short pps_short_126_reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_log_scanout"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_log_scanout extends Struct {
    public Ptr<drm_client_buffer> buffer;

    public Ptr<font_desc> font;

    public @Unsigned int rows;

    public @Unsigned int columns;

    public @Unsigned int scaled_font_h;

    public @Unsigned int scaled_font_w;

    public @Unsigned int line;

    public @Unsigned int format;

    public @Unsigned int px_width;

    public @Unsigned int front_color;

    public @Unsigned int prefix_color;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_log"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_log extends Struct {
    public mutex lock;

    public drm_client_dev client;

    public console con;

    public boolean probed;

    public @Unsigned int n_scanout;

    public Ptr<drm_log_scanout> scanout;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_sysfb_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_sysfb_device extends Struct {
    public drm_device dev;

    public Ptr<java.lang.Character> edid;

    public drm_display_mode fb_mode;

    public Ptr<drm_format_info> fb_format;

    public @Unsigned int fb_pitch;

    public @Unsigned int fb_gamma_lut_size;

    public iosys_map fb_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_sysfb_crtc_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_sysfb_crtc_state extends Struct {
    public drm_crtc_state base;

    public Ptr<drm_format_info> format;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct drm_sysfb_format"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class drm_sysfb_format extends Struct {
    public pixel_format pixel;

    public @Unsigned int fourcc;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int value; enum drm_stat_type type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class AnonymousType1269826537C59 extends Struct {
    public @Unsigned int value;

    public drm_stat_type type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int value; enum drm_stat_type type; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class AnonymousType2081952435C64 extends Struct {
    public @Unsigned long value;

    public drm_stat_type type;
  }
}
